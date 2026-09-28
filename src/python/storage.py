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