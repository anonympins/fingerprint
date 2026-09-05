# Python Integration Guide

This guide details how to integrate and use the `fingerprint` library within a Python ecosystem, supporting both Asynchronous Server Gateway Interface (ASGI) and Web Server Gateway Interface (WSGI) applications.

---

## Prerequisites

*   **Python 3.8+**
*   The `fingerprint` Python package.
*   For ASGI applications: An ASGI-compatible framework (e.g., FastAPI, Starlette, Quart).
*   For WSGI applications: A WSGI-compatible framework (e.g., Flask, Django, Bottle).
*   For external data storage (recommended for production): A compatible asynchronous client for Redis or MongoDB. The `InMemoryStore` is provided for development and testing.

---

## Core Concepts

The Python integration provides middleware components that wrap your existing application. These middlewares intercept incoming requests, apply the fingerprinting logic, and take action (allow, block, challenge, redirect) based on the configured security policy.

---

## ASGI Middleware Integration (FastAPI, Starlette, Quart)

The `ASGIFingerprintMiddleware` is designed for asynchronous Python web frameworks. It integrates seamlessly into your ASGI application stack.

### Example with FastAPI

```python
# main.py
from fastapi import FastAPI, Request, Response
from fingerprint.engine import FastAPIFingerprintMiddleware, InMemoryStore
import uvicorn

app = FastAPI()

# 1. Define your security configuration
security_config = {
    "thresholds": {"low": 20, "high": 75, "block": 95},
    "weights": {
        "inconsistencyScore": 0.8,
        "headerAnomalyScore": 0.1,
        "clientHintsInconsistencyScore": 0.7,
        "tlsSpoofingScore": 0.8,
        "botScore": 1.0,
        "honeypotScore": 1.0,
    },
    "honeypot": {
        "fields": ["email_confirm"],
        "trapUrls": ["/wp-admin", "/.env"]
    },
    "similarityThreshold": 0.7
}

# 2. Initialize the store (use InMemoryStore for development, replace with Redis/MongoDB for production)
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

# 1. Define your security configuration
security_config = {
    # ... (same as FastAPI example) ...
}

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
import asyncio

app = Flask(__name__)

# 1. Define your security configuration
security_config = {
    # ... (same as FastAPI example) ...
}

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

## Configuration Options

The `security_config` dictionary passed to the middleware constructors is identical in structure to the Node.js and PHP configurations. Refer to the Full Configuration Options for a comprehensive list of available properties.

### Key Configuration Properties

*   `thresholds`: (dict) Defines suspicion score thresholds for `low`, `medium`, `high`, and `block` actions.
*   `weights`: (dict) Assigns importance to various suspicion vectors (e.g., `inconsistencyScore`, `honeypotScore`).
*   `honeypot`: (dict) Configures honeypot fields and trap URLs.
*   `cpu`: (dict) Configures CPU Proof-of-Work challenge difficulty.
*   `similarityThreshold`: (float) The minimum similarity score required for fingerprint consistency (default: 0.7).

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

---

## Next Steps

*   Consult the Key Concepts and Suspicion Vectors guide to learn more about how behavioral telemetry is evaluated.
*   Review the Full Configuration Options for all available settings.