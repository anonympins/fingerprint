# Node.js Integration Guide

This guide details how to integrate and use the `fingerprint` library within a Node.js ecosystem, using Express middleware or other raw routing systems.

## Prerequisites

Make sure you have middleware to parse cookies (like `cookie-parser`) and request bodies (like `express.json` and `express.urlencoded`) registered *before* applying the protection middleware.
 
---

## Express.js Middleware Integration

Using `powMiddleware` is the easiest way to protect your Express application.

 ```javascript
 import express from 'express';
 import cookieParser from 'cookie-parser';
 import bodyParser from 'body-parser';
 import { powMiddleware, createSecurityProfile } from '@anonympins/fingerprint';
 
 const app = express();
 app.use(cookieParser());
 app.use(bodyParser.json());
 app.use(bodyParser.urlencoded({ extended: true }));
 
 // 1. Create a security configuration from a preset profile (e.g. balanced, strict, api)
 const securityConfig = createSecurityProfile('balanced', {
     verbose: process.env.NODE_ENV !== 'production',
 });
 
 // 2. Apply the protection middleware
 app.use(powMiddleware(securityConfig));
 
 // 3. Enable trust proxy if your app is behind a reverse proxy (Nginx, Cloudflare...)
 app.set('trust proxy', 1);
 
 app.get('/', (req, res) => {
     res.send('Welcome to the protected page!');
 });
 
 app.listen(3000, () => console.log('Server started on port 3000'));
 ```
 
---

## Raw Node.js HTTP Integration (No Express)

If you are using Koa, Fastify, or the native Node.js `http` module, you can leverage `identifyRequest` manually to process incoming requests and inspect or enforce security decisions.

Below is an example using the native Node.js `http` module:

```javascript
import http from 'http';
import { identifyRequest, createSecurityProfile } from '@anonympins/fingerprint';

const securityConfig = createSecurityProfile('api', {
    verbose: true,
});

const server = http.createServer(async (req, res) => {
    try {
        // Process the request through the fingerprint analyzer.
        // If a challenge needs to be served or the request is blocked,
        // identifyRequest will write to the response and return.
        const identity = await identifyRequest(req, res, securityConfig);

        if (res.headersSent) {
            // The request was intercepted (e.g., PoW challenge served or blocked)
            return;
        }

        // Safe request - proceed with your application logic
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'success', identity }));
    } catch (error) {
        console.error('Security verification error:', error);
        res.writeHead(500);
        res.end('Internal Server Error');
    }
});

server.listen(3000, () => {
    console.log('Secure raw HTTP server listening on port 3000');
});
```

### Koa.js Example

For Koa, you can write a simple middleware wrapper around `identifyRequest`:

```javascript
import Koa from 'koa';
import { identifyRequest, createSecurityProfile } from '@anonympins/fingerprint';

const app = new Koa();
const securityConfig = createSecurityProfile('balanced');

app.use(async (ctx, next) => {
    // identifyRequest expects native Node.js req and res objects
    const identity = await identifyRequest(ctx.req, ctx.res, securityConfig);
    
    if (ctx.res.headersSent) {
        return; // Handled by fingerprint challenge/block UI
    }

    ctx.state.identity = identity;
    await next();
});

app.use((ctx) => {
    ctx.body = `Verified Identity: ${ctx.state.identity}`;
});

app.listen(3000);
```

---

## Next Steps

* See [Full Configuration Options](full_options) to discover all options you can tune.
* See [Client Side Integration](client_side) to enable proactive browser challenges and behavioral trackers.

---

## Serving WebAssembly (WASM) & Client JS Files

If you use WebAssembly to accelerate hashing on the client side, you can let the middleware host `/fp.js` and `/fp.wasm` automatically by configuring the `wasm` property in your `securityConfig`.

Specify the directory containing these built files (relative or absolute):

```javascript
const securityConfig = createSecurityProfile('balanced', {
    verbose: process.env.NODE_ENV !== 'production',
    wasm: './public' // Directory containing fp.js and fp.wasm
});
```

When `wasm` is set, requests to `/fp.js` and `/fp.wasm` will be intercepted and served with the correct MIME types directly.

### Advanced WASM Filename & Path Customization

If you want to rename the files or expose them on different route paths, pass a configuration object instead of a string:

```javascript
const securityConfig = createSecurityProfile('balanced', {
    wasm: {
        jsPath: '/custom-fp.js',         // URL route to serve the client script
        jsFile: './public/custom-fp.js',  // Physical file path on disk
        wasmPath: '/custom-fp.wasm',     // URL route to serve the WASM file
        wasmFile: './public/custom-fp.wasm' // Physical file path on disk
    }
});
```