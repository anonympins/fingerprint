# Ecosystem Integrations

The `fingerprint` library is designed with flexibility in mind, allowing it to be integrated with various datastores and Node.js frameworks beyond the default Express.js middleware. This guide provides practical examples for developers looking to extend the library's capabilities.

The two main extension points are:
1.  **Datastore Integration**: Replacing the default in-memory store with a persistent, scalable datastore like Redis.
2.  **Framework Integration**: Using the core `FingerprintEngine` to protect applications built with other frameworks like Koa or Fastify.

---

## 1. Datastore Integration (`IStore`)

To persist device and IP data across multiple server instances or deployments, you can replace the default in-memory store with any datastore that implements the `IStore` interface.

### The `IStore` Interface

An object compliant with `IStore` must expose the following asynchronous methods:

```typescript
interface IStore {
  /** Retrieves a value for a given key. */
  get(key: string): Promise<any>;

  /**
   * Sets a value for a given key, with an optional Time-To-Live (TTL).
   * The `ttl` is specified in seconds.
   */
  set(key: string, value: any, ttl?: number): Promise<void>;

  /** Checks if a key exists. */
  has(key: string): Promise<boolean>;

  /** Deletes a key. */
  delete(key: string): Promise<void>;
}
```

### Example: Redis Store

Redis is an ideal choice for a distributed datastore due to its speed and support for TTL. Here is a complete example of a Redis store implementation using the popular `redis` package.

**`redis-store.js`**
```javascript
import { createClient } from 'redis';

/**
 * Creates a store implementation for Redis that is compatible with the IStore interface.
 * @param {string} redisUrl - The connection URL for the Redis server.
 * @returns {IStore} An IStore-compatible object.
 */
export function createRedisStore(redisUrl) {
  const client = createClient({ url: redisUrl });
  client.on('error', (err) => console.error('Redis Client Error', err));
  client.connect();

  // Redis stores data as strings, so we need to serialize/deserialize objects.
  // We also need to handle special types like `Set`.
  const serialize = (value) => {
    if (value && typeof value === 'object') {
      // Convert Set to an array before stringifying
      if (value.ips instanceof Set) {
        value.ips = [...value.ips];
      }
    }
    return JSON.stringify(value);
  };

  const deserialize = (value) => {
    if (value === null) return null;
    const obj = JSON.parse(value);
    // Convert the `ips` array back to a Set
    if (obj && Array.isArray(obj.ips)) {
      obj.ips = new Set(obj.ips);
    }
    return obj;
  };

  return {
    async get(key) {
      const value = await client.get(key);
      return deserialize(value);
    },

    async set(key, value, ttl) {
      const serializedValue = serialize(value);
      if (ttl) {
        // Use 'EX' for TTL in seconds
        await client.set(key, serializedValue, { EX: ttl });
      } else {
        await client.set(key, serializedValue);
      }
    },

    async has(key) {
      const result = await client.exists(key);
      return result === 1;
    },

    async delete(key) {
      await client.del(key);
    },

    // Optional: method to gracefully close the connection
    async disconnect() {
      await client.quit();
    }
  };
}
```

**Usage in your application:**

```javascript
import { configureStore } from './fingerprint.js';
import { createRedisStore } from './redis-store.js';

// Initialize and configure the Redis store
const redisStore = createRedisStore(process.env.REDIS_URL);
configureStore(redisStore);

// Now, the powMiddleware will use Redis for all its state management.
```

---

## 2. Web Framework Integration

While the library provides a convenient `powMiddleware` for Express, the core logic is contained within the `FingerprintEngine` class. This allows for integration into any Node.js framework.

The general workflow is detailed in the `README.md` under "Manual Integration". Here are specific examples for Koa and Fastify.

### Example: Koa.js Middleware

This example shows how to wrap `FingerprintEngine` in a Koa middleware.

```javascript
import Koa from 'koa';
import { FingerprintEngine } from './fingerprint.js';

const app = new Koa();

const securityConfig = { /* ... your security configuration ... */ };
const engine = new FingerprintEngine(securityConfig);

app.use(async (ctx, next) => {
    // 1. Build the requestContext from Koa's context (ctx)
    const requestContext = {
        clientIp: ctx.ip,
        path: ctx.path,
        cookies: ctx.cookies.get.length > 0 ? ctx.cookies : {}, // Koa's cookie handling is different
        query: ctx.query,
        body: ctx.request.body, // Requires a body parser middleware like koa-bodyparser
        headers: ctx.headers,
        rawHeaders: ctx.req.rawHeaders,
        httpVersion: ctx.req.httpVersion,
        isStatic: (path) => path.startsWith('/public') // Example static check
    };

    // 2. Process the request
    const decision = await engine.processRequest(requestContext);

    // Attach score to context for downstream use
    ctx.state.fingerprint = { score: decision.score, vector: decision.vector };

    // Handle new cookies that need to be set
    if (requestContext._newCookies) {
        requestContext._newCookies.forEach(c => ctx.cookies.set(c.name, c.value, c.options));
    }

    // 3. Act on the decision
    switch (decision.action) {
        case 'block':
            ctx.status = decision.status;
            ctx.body = decision.body;
            break;
        case 'challenge':
            ctx.status = decision.status;
            ctx.type = 'text/html';
            ctx.body = decision.body;
            break;
        case 'redirect':
            if (decision.cookie) {
                ctx.cookies.set(decision.cookie.name, decision.cookie.value, decision.cookie.options);
            }
            ctx.redirect(decision.path);
            break;
        case 'next':
        default:
            await next(); // Proceed to the next middleware
            break;
    }
});

app.use(async (ctx) => {
    ctx.body = `Welcome! Your suspicion score is: ${ctx.state.fingerprint.score}`;
});

app.listen(3000, () => console.log('Koa server with fingerprint protection started on port 3000'));
```

### Example: Fastify Plugin

For Fastify, you can create a plugin that uses a `preHandler` hook to run the fingerprint check before your route logic.

```javascript
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import { FingerprintEngine } from './fingerprint.js';

const fastify = Fastify({ logger: true });

const securityConfig = { /* ... your security configuration ... */ };
const engine = new FingerprintEngine(securityConfig);

fastify.register(fastifyCookie);

fastify.addHook('preHandler', async (request, reply) => {
    const requestContext = {
        clientIp: request.ip,
        path: request.raw.url.split('?')[0],
        cookies: request.cookies,
        query: request.query,
        body: request.body,
        headers: request.headers,
        rawHeaders: request.raw.rawHeaders,
        httpVersion: request.raw.httpVersion,
        isStatic: (path) => path.startsWith('/static')
    };

    const decision = await engine.processRequest(requestContext);

    request.fingerprint = { score: decision.score, vector: decision.vector };

    if (requestContext._newCookies) {
        requestContext._newCookies.forEach(c => reply.setCookie(c.name, c.value, c.options));
    }

    if (decision.action !== 'next') {
        if (decision.cookie) {
            reply.setCookie(decision.cookie.name, decision.cookie.value, decision.cookie.options);
        }
        if (decision.action === 'redirect') {
            reply.redirect(decision.path);
        } else { // block or challenge
            reply.code(decision.status).type('text/html').send(decision.body);
        }
    }
    // If 'next', the hook completes and request processing continues.
});

fastify.get('/', async (request, reply) => {
    return { message: 'Welcome!', score: request.fingerprint.score };
});

fastify.listen({ port: 3000 }, (err) => {
    if (err) throw err;
    console.log('Fastify server with fingerprint protection started on port 3000');
});
```