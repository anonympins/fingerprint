import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rustDir = path.join(__dirname, "src", "rust");
const targetWasm = path.join(
    rustDir,
    "target",
    "wasm32-unknown-unknown",
    "release",
    "fingerprint_wasm.wasm"
);
const publicDir = path.join(__dirname, "public");
const outputWasm = path.join(publicDir, "fp.wasm");

try {
    const installedTargets = execSync("rustup target list --installed", { encoding: "utf8" });
    if (!installedTargets.includes("wasm32-unknown-unknown")) {
        console.log("[wasm] Adding missing target wasm32-unknown-unknown via rustup...");
        execSync("rustup target add wasm32-unknown-unknown", { stdio: "inherit" });
    }
} catch {
    console.warn(
        "[wasm] Warning: Unable to query rustup targets. Ensure wasm32-unknown-unknown is installed."
    );
}

console.log("[wasm] Compiling Rust to wasm32-unknown-unknown with SIMD128...");

try {
    execSync("cargo build --target wasm32-unknown-unknown --release", {
        cwd: rustDir,
        env: {
            ...process.env,
            RUSTFLAGS: "-C target-feature=+simd128"
        },
        stdio: "inherit"
    });

    if (!fs.existsSync(publicDir)) {
        fs.mkdirSync(publicDir, { recursive: true });
    }

    fs.copyFileSync(targetWasm, outputWasm);

    const stat = fs.statSync(outputWasm);
    console.log(
        `[wasm] Successfully generated ${outputWasm} (${(stat.size / 1024).toFixed(2)} KB)`
    );
} catch (error) {
    console.error("\n[wasm] Compilation failed. Ensure that wasm32-unknown-unknown is installed (`rustup target add wasm32-unknown-unknown`).");
    process.exit(1);
}