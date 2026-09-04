# API Reference

This document provides the reference for the main public APIs exported by the `fingerprint` library.

---

## Node.js public API

### Core Methods

#### `powMiddleware(securityConfig)`
Creates an Express-compliant middleware.
* **Returns**: `Function` (Express middleware)

#### `identifyRequest(req, res)`
Analyzes the request outside Express middleware to return a stateful identifier.
* **Returns**: `Promise<string>` (e.g. `device:<id>`, `suspicious_high:<ip>`)

---

### Helpers & Builders

#### `createSecurityProfile(profileName, overrides)`
Generates a configuration preset deeply merged with your overrides.
* **Parameters**: 
  * `profileName`: `'balanced' | 'strict' | 'api' | 'blog' | 'ecommerce'`
  * `overrides`: `object`

#### `FingerprintBuilder`
Allows constructing server-side fingerprints manually.
```javascript
import { FingerprintBuilder } from '@anonympins/fingerprint';

const builder = new FingerprintBuilder();
builder.add('user_agent', req.headers['user-agent']);
const hash = builder.toString();
```

---

### Datastores Configuration

#### `configureStore(storeImplementation)`
Replaces the default in-memory store with an external backend.

```javascript
// MongoDB Example
import { configureStore } from '@anonympins/fingerprint';
import { createMongoDbStore } from '@anonympins/fingerprint/mongodb';
import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URL);
await client.connect();
configureStore(createMongoDbStore(client.db('dbname'), 'sessions_collection'));
```

---

## PHP public API

### Class: `Anonympins\Fingerprint\DirectFingerprint`

The main class to orchestrate script protection.

#### `__construct(array $config)`
Initializes the protection engine with a configuration.

#### `protect(): array`
Analyzes the current superglobals, headers, and environment. If malicious/suspicious, executes challenge output or blocks immediately, calling `exit()`.
If safe, returns the calculated score and vector.

---

### Class: `Anonympins\Fingerprint\Config\SecurityProfiles`

#### `public static function createSecurityProfile(string $profileName, array $overrides = []): array`
Creates a customized profile preset.
* **Parameters**: 
  * `$profileName`: `'balanced' | 'strict' | 'api' | 'blog' | 'ecommerce'`
  * `$overrides`: `array`

---

### Class: `Anonympins\Fingerprint\Store\StoreManager`

#### `public static function configureStore(IStore $store): void`
Switches store engines for sessions, nonces, and IP history.

```php
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Store\RedisStore;

StoreManager::configureStore(new RedisStore($redisConnection));
```