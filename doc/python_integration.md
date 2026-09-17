# Python Integration Guide (with SecurityProfiles)

This guide details how to integrate and use the `fingerprint` library within a Python ecosystem, supporting both Asynchronous Server Gateway Interface (ASGI) and Web Server Gateway Interface (WSGI) applications, leveraging the powerful `SecurityProfiles` helper.

---

## Prerequisites

*   **Python 3.8+**
*   The `fingerprint` Python package.
*   For ASGI applications: An ASGI-compatible framework (e.g., FastAPI, Starlette, Quart).
*   For WSGI applications: A WSGI-compatible framework (e.g., Flask, Django, Bottle).
*   For external data storage: A compatible client for Redis or MongoDB (the `InMemoryStore` is provided for development and testing).

---

## Core Concepts

The Python integration provides middleware components that wrap your existing application. These middlewares intercept incoming requests, apply the fingerprinting logic, and take action (allow, block, challenge, redirect) based on the configured security policy.

---

## Security Profiles

The Python library includes a `SecurityProfiles` helper to quickly bootstrap configurations for common use cases while allowing deep overrides.

Available built-in profiles are:
*   `"balanced"`: General-purpose configuration, balanced security, and user experience.
*   `"strict"`: Aggressive security suitable for admin panels or sensitive portals.
*   `"api"`: Tailored for API endpoints with high sensitivity to rate, velocity, and patterns.
*   `"blog"`: Content-heavy optimization focusing on scraping protection and spam mitigation.

### Loading a Security Profile

```python
from fingerprint.security_profiles import SecurityProfiles

# Load the default balanced profile
security_config = SecurityProfiles.create_security_profile("balanced")

# Load a profile with specific overrides
custom_config = SecurityProfiles.create_security_profile(
    profile_name="api",
    overrides={
        "thresholds": {
            "low": 15,  # Override low threshold
        },
        "honeypot": {
            "fields": ["custom_trap_field"]
        }
    }
)
```

---

## ASGI Middleware Integration (FastAPI, Starlette, Quart)

The `ASGIFingerprintMiddleware` is designed for asynchronous Python web frameworks. It integrates seamlessly into your ASGI application stack.

### Example with FastAPI

```python
# main.py
from fastapi import FastAPI, Request, Response
from fingerprint.engine import FastAPIFingerprintMiddleware, InMemoryStore
from fingerprint.security_profiles import SecurityProfiles
import uvicorn

app = FastAPI()

# 1. Generate security configuration using SecurityProfiles
security_config = SecurityProfiles.create_security_profile(
    profile_name="balanced",
    overrides={
        "honeypot": {
            "fields": ["email_confirm"],
            "trap_urls": ["/wp-admin", "/.env"]
        }
    }
)

# 2. Initialize the store (InMemoryStore for dev; use Redis/MongoDB in production)
fingerprint_store = InMemoryStore()

# 3. Add the Fingerprint Middleware to your FastAPI application
app.add_middleware(
    FastAPIFingerprintMiddleware,
    security_config=security_config,
    store=fingerprint_store
)

@app.get("/")
async def read_root():
    return {"message": "Welcome to the protected API!"}

@app.post("/submit")
async def submit_data(request: Request):
    # Your application logic here
    return {"status": "Data received"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### Raw ASGI Integration

For other ASGI frameworks or custom ASGI applications, you can directly wrap your application with `ASGIFingerprintMiddleware`:

```python
# app.py
from fingerprint.engine import ASGIFingerprintMiddleware, InMemoryStore
from fingerprint.security_profiles import SecurityProfiles

async def my_asgi_app(scope, receive, send):
    # Your ASGI application logic here
    if scope['type'] == 'http':
        await send({
            'type': 'http.response.start',
            'status': 200,
            'headers': [[b'content-type', b'text/plain']],
        })
        await send({
            'type': 'http.response.body',
            'body': b'Hello from my protected ASGI app!',
        })

# 1. Generate security configuration using SecurityProfiles
security_config = SecurityProfiles.create_security_profile(
    profile_name="balanced",
    overrides={
        "honeypot": {
            "fields": ["email_confirm"],
            "trap_urls": ["/wp-admin", "/.env"]
        }
    }
)

# 2. Initialize the store
fingerprint_store = InMemoryStore()

# 3. Wrap your ASGI application
protected_asgi_app = ASGIFingerprintMiddleware(
    my_asgi_app,
    security_config=security_config,
    store=fingerprint_store
)

# To run with Uvicorn: uvicorn app:protected_asgi_app --port 8000
```

---

## WSGI Middleware Integration (Flask, Django, Bottle)

The `WSGIFingerprintMiddleware` is designed for synchronous Python web frameworks. It handles the necessary asynchronous bridging internally to interact with the fingerprint engine.

### Example with Flask

```python
# app.py
from flask import Flask, request, jsonify
from fingerprint.engine import WSGIFingerprintMiddleware, InMemoryStore
from fingerprint.security_profiles import SecurityProfiles
import asyncio

app = Flask(__name__)

# 1. Generate security configuration using SecurityProfiles
security_config = SecurityProfiles.create_security_profile(
    profile_name="balanced",
    overrides={
        "honeypot": {
            "fields": ["email_confirm"],
            "trap_urls": ["/wp-admin", "/.env"]
        }
    }
)

# 2. Initialize the store
fingerprint_store = InMemoryStore()

# 3. Wrap your Flask application with the WSGI middleware
app.wsgi_app = WSGIFingerprintMiddleware(
    app.wsgi_app,
    security_config=security_config,
    store=fingerprint_store
)

@app.route("/")
def index():
    return "Welcome to the protected Flask app!"

@app.route("/api/data", methods=["GET", "POST"])
def api_data():
    return jsonify({"message": "Protected API data"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

---

## Automatic Ed25519 Key Generation

You can enable automatic, zero-dependency, on-load key generation if no pre-generated keys are configured in your environment.

To activate this, set `useAsymmetricTickets` to `True` in your security configuration (via overrides or directly in the profile structure):

```python
security_config = SecurityProfiles.create_security_profile(
    profile_name="balanced",
    overrides={
        "useAsymmetricTickets": True
    }
)
```

The engine will automatically generate a highly secure ephemeral Ed25519 key pair on load using the standard `cryptography` package, storing them in `os.environ["ED25519_PRIVATE_KEY"]` and `os.environ["ED25519_PUBLIC_KEY"]` transparently.

---

## Customizing the Store

By default, the middlewares use `InMemoryStore`, which is suitable for development but **not recommended for production** as data is lost when the application restarts.

For production environments, you should implement an `IStore` interface that connects to a persistent database like Redis or MongoDB. The `InMemoryStore` class serves as a template for this interface.

```python
# Example of a custom Redis store (conceptual)
import redis
import json

class RedisStore:
    def __init__(self, host='localhost', port=6379, db=0):
        self._redis = redis.Redis(host=host, port=port, db=db)

    async def get(self, key: str) -> Optional[Any]:
        value = self._redis.get(key)
        return json.loads(value) if value else None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        if ttl:
            self._redis.setex(key, ttl, json.dumps(value))
        else:
            self._redis.set(key, json.dumps(value))

    async def has(self, key: str) -> bool:
        return self._redis.exists(key) > 0

    async def delete(self, key: str) -> None:
        self._redis.delete(key)

# Then, pass an instance of RedisStore to your middleware:
# fingerprint_store = RedisStore(host='your_redis_host')
# app.add_middleware(FastAPIFingerprintMiddleware, security_config=security_config, store=fingerprint_store)
```