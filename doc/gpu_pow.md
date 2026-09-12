# GPU Proof-of-Work (Chaotic Logistic Map PoW)

Our fingerprinting security suite includes an asymmetric GPU Proof-of-Work (PoW) designed to run massively parallel floating-point computations in the browser (via WebGPU with a WebGL2 fallback).

How it works:
## Critical Triggering Strategy

To balance optimal security with user experience (UX) and power consumption, the GPU PoW is **never triggered systematically**. Instead, it is reserved for critical checkpoints:

1. **High Suspicion Thresholds:** Triggered only when the progressive suspicion score exceeds the `high` threshold (e.g., $\ge 75$), signaling anomalous behavior or inconsistent fingerprint layers.
2. **Headless & Emulator Detection:** Specifically issued when fingerprint analysis suspects the use of CPU-based WebGL/WebGPU renderers (such as SwiftShader or soft-pipe drivers) to force the client into a heavy, single-threaded execution bottleneck.
3. **Sensitive Endpoint Protection:** Can be strictly enforced on critical transactional routes (e.g., `/api/checkout`, `/login`, `/api/v1/auth`) to raise the economic cost for botnet operators attempting credential stuffing or inventory scalping.

### UX & Resource Mitigation
* **Standard Users:** Remain completely unaffected under normal browsing behavior (score < `low`).
* **Suspicious Users:** Solve the parallel chaotic map in less than **50ms** on native mobile/desktop GPUs.
* **Headless Bots:** Get choked for **3000ms to 8000ms** due to non-linear float32 math emulation on virtualized single-threaded CPUs.

### Chaotic Logistic Map
We utilize a logistic map in the chaotic regime ($r = 3.9999$) to calculate chaotic floating-point trajectories across 64 parallel channels:

$$x_{n+1} = r \times x_n \times (1.0 - x_n)$$

The computations are initiated with:

$$x_0 = \text{SeedFloat} + \text{channel\\_index} \times 0.015$$

Because the trajectory is highly sensitive to initial conditions, a chaotic cascade occurs. On dedicated GPU hardware, these parallel calculations complete in milliseconds, whereas single-threaded CPU emulators (such as SwiftShader commonly used by headless bots) take several seconds to compute.


## Server-Side Verification

To keep server-side verification extremely lightweight ($O(1)$) and immune to Denial of Service (DoS) attacks, the server does not compute all 64 trajectories. Instead, it selects a subset of indices (e.g. `[0, 12, 35, 57]`) and recalculates only those 32-bit single-precision trajectories to verify client honesty with a tiny tolerance threshold ($10^{-4}$).

## Features
* **Ultra-Fast Server Verification:** Only verifies a small sample of channel trajectories.
* **Headless Bot Mitigation:** Emulated CPU WebGL/WebGPU layers are choked by non-linear floating-point iterations.
* **Zero External Dependencies:** Native implementation across JavaScript, PHP, and Python.
* **Cross-Platform Consistency:** Uses `Math.fround` (JS) and exact float 32-bit packing (PHP/Python) to ensure bit-perfect compatibility.
```