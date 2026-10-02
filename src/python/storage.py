import time
import json
import datetime
from typing import Any, Dict, Optional


class InMemoryStore:
    """
    A simple in-memory key-value store implementation with TTL support.
    """
    def __init__(self):
        self._store: Dict[str, Any] = {}
        self._expires: Dict[str, float] = {}

    async def get(self, key: str) -> Optional[Any]:
        if key in self._expires and self._expires[key] < time.time():
            await self.delete(key)
            return None
        return self._store.get(key)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        self._store[key] = value
        if ttl:
            self._expires[key] = time.time() + ttl
        elif key in self._expires:
            del self._expires[key]

    async def has(self, key: str) -> bool:
        if key in self._expires and self._expires[key] < time.time():
            await self.delete(key)
            return False
        return key in self._store

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._expires.pop(key, None)

    async def set_nx(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        if await self.has(key):
            return False
        await self.set(key, value, ttl=ttl)
        return True

    async def incr(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        current = await self.get(key)
        new_val = (int(current) if current is not None else 0) + amount
        await self.set(key, new_val, ttl=ttl)
        return new_val

    async def hget(self, key: str, field: str) -> Optional[Any]:
        data = await self.get(key)
        if isinstance(data, dict):
            return data.get(field)
        return None

    async def hset(self, key: str, field: str, value: Any, ttl: Optional[int] = None) -> None:
        data = await self.get(key)
        if not isinstance(data, dict):
            data = {}
        data[field] = value
        await self.set(key, data, ttl=ttl)

    async def hincrby(self, key: str, field: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        data = await self.get(key)
        if not isinstance(data, dict):
            data = {}
        new_val = int(data.get(field, 0)) + amount
        data[field] = new_val
        await self.set(key, data, ttl=ttl)
        return new_val


class RedisStore:
    """
    Production-grade Redis adapter for FingerprintEngine.
    Handles serialization, deserialization, and Set-to-list conversions.
    """
    def __init__(self, redis_client):
        self._client = redis_client

    def _serialize(self, value: Any) -> str:
        def convert(obj):
            if isinstance(obj, set):
                return list(obj)
            return obj
        return json.dumps(value, default=convert)

    def _deserialize(self, value: str) -> Any:
        obj = json.loads(value)
        if isinstance(obj, dict) and "ips" in obj and isinstance(obj["ips"], list):
            obj["ips"] = set(obj["ips"])
        return obj

    async def get(self, key: str) -> Optional[Any]:
        val = await self._client.get(key)
        if not val:
            return None
        return self._deserialize(val.decode("utf-8") if isinstance(val, bytes) else val)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        val_str = self._serialize(value)
        if ttl:
            await self._client.setex(key, ttl, val_str)
        else:
            await self._client.set(key, val_str)

    async def has(self, key: str) -> bool:
        return await self._client.exists(key) > 0

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def set_nx(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        val_str = self._serialize(value)
        res = await self._client.set(key, val_str, ex=ttl, nx=True)
        return bool(res)

    async def incr(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        if ttl:
            pipe = self._client.pipeline()
            pipe.incrby(key, amount)
            pipe.expire(key, ttl)
            res = await pipe.execute()
            return res[0]
        return await self._client.incrby(key, amount)

    async def hget(self, key: str, field: str) -> Optional[Any]:
        val = await self._client.hget(key, field)
        if val is None:
            return None
        return self._deserialize(val.decode("utf-8") if isinstance(val, bytes) else val)

    async def hset(self, key: str, field: str, value: Any, ttl: Optional[int] = None) -> None:
        val_str = self._serialize(value)
        if ttl:
            pipe = self._client.pipeline()
            pipe.hset(key, field, val_str)
            pipe.expire(key, ttl)
            await pipe.execute()
        else:
            await self._client.hset(key, field, val_str)

    async def hincrby(self, key: str, field: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        if ttl:
            pipe = self._client.pipeline()
            pipe.hincrby(key, field, amount)
            pipe.expire(key, ttl)
            res = await pipe.execute()
            return res[0]
        return await self._client.hincrby(key, field, amount)

    async def rate_limit_token_bucket(
        self,
        key: str,
        capacity: float,
        refill_rate: float,
        now: float,
        cost: float = 1.0,
        ttl: int = 3600
    ) -> bool:
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local cost = tonumber(ARGV[4])
        local ttl = tonumber(ARGV[5])

        local data = redis.call('HMGET', key, 'tokens', 'lastRefill')
        local tokens = tonumber(data[1])
        local last_refill = tonumber(data[2])

        if not tokens or not last_refill then
            tokens = capacity
            last_refill = now
        else
            local elapsed = math.max(0, now - last_refill)
            tokens = math.min(capacity, tokens + (elapsed * refill_rate))
            last_refill = now
        end

        if tokens < cost then
            redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', last_refill)
            redis.call('EXPIRE', key, ttl)
            return 0
        else
            tokens = tokens - cost
            redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', last_refill)
            redis.call('EXPIRE', key, ttl)
            return 1
        end
        """
        res = await self._client.eval(lua_script, 1, key, capacity, refill_rate, now, cost, ttl)
        return bool(res == 1)


class MongoDbStore:
    """
    Production-grade MongoDB adapter using motor or pymongo async.
    """
    def __init__(self, collection):
        self._collection = collection

    def _serialize(self, value: Any) -> str:
        def convert(obj):
            if isinstance(obj, set):
                return list(obj)
            return obj
        return json.dumps(value, default=convert)

    def _deserialize(self, value: str) -> Any:
        obj = json.loads(value)
        if isinstance(obj, dict) and "ips" in obj and isinstance(obj["ips"], list):
            obj["ips"] = set(obj["ips"])
        return obj

    async def get(self, key: str) -> Optional[Any]:
        doc = await self._collection.find_one({"_id": key})
        if not doc:
            return None
        if "expiresAt" in doc:
            expires_at = doc["expiresAt"]
            now = datetime.datetime.now(datetime.timezone.utc)
            if expires_at.tzinfo is None:
                now = datetime.datetime.utcnow()
            if expires_at < now:
                await self.delete(key)
                return None
        return self._deserialize(doc["value"])

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        doc = {
            "_id": key,
            "value": self._serialize(value)
        }
        if ttl:
            doc["expiresAt"] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl)
        await self._collection.replace_one({"_id": key}, doc, upsert=True)

    async def has(self, key: str) -> bool:
        doc = await self._collection.find_one({"_id": key}, {"expiresAt": 1})
        if not doc:
            return False
        if "expiresAt" in doc:
            expires_at = doc["expiresAt"]
            now = datetime.datetime.now(datetime.timezone.utc)
            if expires_at.tzinfo is None:
                now = datetime.datetime.utcnow()
            if expires_at < now:
                await self.delete(key)
                return False
        return True

    async def delete(self, key: str) -> None:
        await self._collection.delete_one({"_id": key})

    async def init(self) -> None:
        import pymongo
        await self._collection.create_index([("expiresAt", pymongo.ASCENDING)], expireAfterSeconds=0)