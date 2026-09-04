# Client-Side Integration Guide

The client-side companion library of the `fingerprint` engine is responsible for collecting hardware telemetry, analyzing human-behavioral characteristics (mouse movements, keystroke dynamics, click variance), managing trap fields (honeypots), and solving Proof-of-Work (PoW/uPoW) challenges directly in the user's browser.

---

## Loading the Script

You can integrate either the standard client script or the obfuscated version (recommended for production to prevent reverse-engineering of behavioral tracking algorithms).

### Option A: Static HTML Delivery

Copy the client file from `node_modules/@anonympins/fingerprint/dist/` or your vendor directory to your public assets directory:

```html
<!-- Recommended for production: Obfuscated version -->
<script src="/assets/js/fingerprint.client.obfuscated.js"></script>
```

### Option B: ES Module Import

If you are building your frontend application with an asset bundler (Webpack, Vite, Rollup):

```javascript
import { initializeClient } from '@anonympins/fingerprint/client';
```

---

## Initialization and Configuration

Once loaded, initialize the client tracker. The client will automatically monitor environmental capabilities and physical interactions (such as mouse movements and keyboard events) to construct legitimacy signals.

```javascript
const fp = window.Fingerprint.initializeClient({
    // Path to the WebAssembly utility for high-performance cryptographic solving (v0.3.2+)
    wasmPath: '/assets/wasm/hashing.wasm',
    
    // Selectors for automatic click variance and honeypot validation
    honeypotSelector: '.fp-trap-field',
    
    // Enable advanced behavioral tracking immediately
    trackBehavior: true
});
```

### Configuration Options Reference

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `wasmPath` | `string` | `undefined` | Path or URI to the compiled WebAssembly solver module. If loaded, cryptographic tasks use WASM for near-native execution speed. |
| `honeypotSelector` | `string` | `'.fp-honeypot'` | CSS Selector used to identify, monitor, and process input elements acting as spam-traps. |
| `trackBehavior` | `boolean` | `true` | Enables active physical interaction analytics (mouse trajectory, keypress speeds, click coordinate variances). |

---

## Capturing Client-Side Events

Starting in **v0.3.3**, the client-side library implements an Event Emitter lifecycle. You can hook into these events to update your application's user interface, trigger custom loaders, or send analytics.

```javascript
// Hook into verification challenges
fp.on('challenge_issued', (event) => {
    console.warn(`[Security] Proof-of-Work challenge issued. Difficulty target: ${event.difficulty} bits.`);
    // Example UI action: Show a customized overlay or screen blocker
    showSecurityOverlay('Verifying your browser legitimacy, please wait...');
});

fp.on('challenge_solved', (event) => {
    console.log(`[Security] Challenge successfully solved in ${event.duration}ms.`);
    // Example UI action: Hide the overlay
    hideSecurityOverlay();
});

fp.on('honeypot_triggered', (event) => {
    console.error(`[Security] Honeypot interaction detected on field: ${event.fieldName}`);
    // Immediate proactive local defense (e.g. graying out the form submission button)
    document.getElementById('submit-btn').disabled = true;
});
```

---

## Honeypot Integration (Forms Protection)

Honeypotting is a highly effective way to instantly trap automated bots. You must include input fields that are physically hidden from human eyes (using CSS absolute off-screen positioning) but remain visible to scrapers parsing raw HTML.

### Step 1: Add Fields to your Forms

Include the trap fields in your registration, login, or comment forms. Make sure the names match those specified in your `securityConfig.honeypot.fields` option (e.g. `email_confirm`, `admin`, `user_nickname`).

```html
<form id="secure-form" action="/submit" method="POST">
    <!-- Legitimate human fields -->
    <label for="email">Email</label>
    <input type="email" id="email" name="email" required />
    
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required />

    <!-- Invisible Honeypot Trap Fields -->
    <div class="fp-trap-container" aria-hidden="true">
        <label class="fp-trap-label" for="email_confirm">Please leave this field empty:</label>
        <input type="text" id="email_confirm" class="fp-trap-field" name="email_confirm" tabindex="-1" autocomplete="off" />
        
        <label class="fp-trap-label" for="user_nickname">Do not write here:</label>
        <input type="text" id="user_nickname" class="fp-trap-field" name="user_nickname" tabindex="-1" autocomplete="off" />
    </div>

    <button type="submit" id="submit-btn">Submit Application</button>
</form>
```

### Step 2: Apply CSS to Hide the Honeypot

Do **not** use `display: none` on the inputs directly, as sophisticated scrapers check for hidden CSS properties. Instead, use absolute positioning or scale transforms to push the container outside the visible viewport.

```css
.fp-trap-container {
    position: absolute;
    left: -99999px;
    top: -99999px;
    width: 1px;
    height: 1px;
    overflow: hidden;
    opacity: 0;
}

.fp-trap-label {
    display: none;
}
```

---

## Under the Hood: Telemetry Mechanics

### Click Variance Score
To intercept precise bot clicks on forms, the client tracks coordinates of physical clicks on interactive nodes.
* **Human behaviour**: Natural physical interactions are imperfect. Submissions from humans will present variable `(x, y)` coordinate offsets relative to the element boundaries.
* **Bot execution**: Interface automation engines (e.g. Puppeteer/Selenium clicking at exact centers) generate zero coordinate variance, automatically increasing their threat rating.

### WebAssembly (WASM) Hashing Accelerator
When a cryptographic PoW/uPoW challenge is triggered (due to a high suspicion score), the client can download and load a static WebAssembly module:
* **With WASM**: Cryptographic evaluations are compiled into near-native byte-code. Your client solves challenges 5x to 10x faster, resulting in zero noticeable delay or CPU throttling.
* **Without WASM (Fallback)**: If the WebAssembly file fails to load or browser support is absent, the client seamlessly falls back to the pure JavaScript cryptographic engine.

---

## Next Steps

* Consult the [Key Concepts and Suspicion Vectors guide](concepts) to learn more about how behavioral telemetry is evaluated.
* Back to [Node.js Integration Guide](nodejs_integration).
* Back to [PHP Integration Guide](php_integration).