# Configuring Ed25519 Asymmetric Keys

The protection engine includes a **Stateless Ticket** validation system. By default, these tickets are secured symmetrically using AES-256-CBC encryption and signed with HMAC-SHA256.

By configuring an **Ed25519** asymmetric key pair, you benefit from:
*   **Enhanced security**: The private key used to sign tickets does not need to be present on exposed validation servers (which only require the public key).
*   **Excellent performance**: Ed25519 offers short signatures and ultra-fast validation times without requiring access to your database.
*   **Zero coupling**: No shared secret needs to be synchronized across your entire infrastructure.

---

## 1. Generating Ed25519 Keys

The private key must be in **PKCS#8 PEM** format, and the public key in **SPKI PEM** format. You can generate them in three different ways.

### Option A: Via the OpenSSL command line (Recommended)

Run the following commands in your terminal:

```bash
# 1. Generate the private key in PKCS#8 format
openssl genpkey -algorithm ed25519 -out private.pem

# 2. Extract the corresponding public key in SPKI format
openssl pkey -in private.pem -pubout -out public.pem
```

### Option B: Via a Node.js script

You can use the native `crypto` module to generate and output your keys:

```javascript
import { generateKeyPairSync } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
publicKeyEncoding: { format: 'pem', type: 'spki' }
});

console.log("--- PRIVATE KEY (ED25519_PRIVATE_KEY) ---");
console.log(privateKey);

console.log("--- PUBLIC KEY (ED25519_PUBLIC_KEY) ---");
console.log(publicKey);
```

### Option C: Via a PHP script

If your environment has the `openssl` extension (PHP 8.0+), you can use this script:

```php
<?php
if (!defined('OPENSSL_KEYTYPE_ED25519')) {
die("Ed25519 is not supported by your version of OpenSSL/PHP.\n");
}

$pkey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_ED25519]);
openssl_pkey_export($pkey, $privateKeyPem);
$details = openssl_pkey_get_details($pkey);
$publicKeyPem = $details['key'];

echo "--- PRIVATE KEY (ED25519_PRIVATE_KEY) ---\n" . $privateKeyPem . "\n";
echo "--- PUBLIC KEY (ED25519_PUBLIC_KEY) ---\n" . $publicKeyPem . "\n";
```

---

## 2. Environment Configuration

For the engine to detect and use the keys, you must declare two environment variables.

### Handling line breaks (`\n`) in `.env` files

PEM keys inherently contain line breaks. In `.env` files (e.g., via `dotenv` in Node or `vlucas/phpdotenv` in PHP), actual line breaks can cause issues. **The protection engine natively handles the following two formats:**

#### Format 1: Actual line breaks (with quotes)
```env
ED25519_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIP8WOfnN3k28u0B69UjV7yMvI9n7pP+qN6w7z4m6v7vX
-----END PRIVATE KEY-----"

ED25519_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA/xY5+c3eTby7QHr1SNXvIy8j2fuk/6o3rDvPibq/u9c=
-----END PUBLIC KEY-----"
```

#### Format 2: Line breaks escaped as `\n` (Recommended for CI/CD and Docker)
The engine will automatically replace the literal character sequences `\\n` with actual line breaks:
```env
ED25519_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIP8WOfnN3k28u0B69UjV7yMvI9n7pP+qN6w7z4m6v7vX\n-----END PRIVATE KEY-----"
ED25519_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA/xY5+c3eTby7QHr1SNXvIy8j2fuk/6o3rDvPibq/u9c=\n-----END PRIVATE KEY-----"
```

---

## 3. Automatic Fallback Mechanism

The engine is designed to be resilient to failures or missing configurations:

1. **Signing (`generateStatelessTicket`)**:
* If If `ED25519_PRIVATE_KEY` is defined, the engine attempts to sign the ticket asymmetrically. A ticket generated in this way will begin with the prefix `ed25519.`.
* If the key is missing or the signature fails (e.g., corrupted key), the engine **automatically and transparently switches** to symmetric mode (AES-256-CBC + HMAC). An error is then logged in verbose mode.

2. **Validation (`parseStatelessTicket` / `isTicketValid`)**:
* If the ticket starts with `ed25519.`, the engine mandates the use of `ED25519_PUBLIC_KEY` to validate the cryptographic signature.
* If the ticket lacks this prefix, the engine uses standard symmetric validation and decryption.

---
