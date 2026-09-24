import {promises as fs} from 'node:fs';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {exec} from 'node:child_process';
import JavaScriptObfuscator from 'javascript-obfuscator';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Attempts to run the build command for the WASM module.
 * Does not fail the build if the command fails (e.g. em++ not found).
 */
function buildWasm() {
  return new Promise((resolve) => {
    console.log('Attempting to build WASM module (optional)...');
    const command = "em++ -msimd128 src/cpp/main.cpp src/cpp/utils.cpp -o public/fp.js -s WASM=1 -s MODULARIZE=1 -s EXPORT_NAME='createFingerprintModule' -s \"EXPORTED_FUNCTIONS=['_malloc','_free','_hash_string','_solve_cpu_target','_solve_memory_challenge','_generate_gpu_pow_trajectory']\" -O3 --no-entry";
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.warn('WASM build failed (this is optional and can be ignored):', stderr);
      } else {
        console.log('WASM module built successfully.');
      }
      resolve(); // Always resolve the promise so the main build is not blocked.
    });
  });
}

async function buildClientScript() {
  try {
    console.log('Reading client script...');
    const clientScriptPath = join(__dirname, 'fingerprint.client.js');
    const clientScriptContent = await fs.readFile(clientScriptPath, 'utf-8');

    console.log('Obfuscating client script...');
    const obfuscationResult = JavaScriptObfuscator.obfuscate(clientScriptContent, {
      compact: true,
      controlFlowFlattening: true, // Flattens control flow
      deadCodeInjection: true, // Injects dead code
      stringArray: true,
      stringArrayRotate: true, // Rotates the string array
      stringArrayShuffle: true, // Shuffles the string array
      // Using a fixed seed yields deterministic obfuscation. For unique builds, use Math.random()
      seed: Math.random(),
      selfDefending: true,
    });

    const obfuscatedCode = obfuscationResult.getObfuscatedCode();

    console.log('Writing obfuscated script to fingerprint.client.obfuscated.js...');
    await fs.writeFile(join(__dirname, './fingerprint.client.obfuscated.js'), obfuscatedCode);

    console.log('Client script build process completed successfully.');
  } catch (error) {
    console.error('Error during client script build:', error);
    process.exit(1);
  }
}

async function main() {
  await buildClientScript();
  await buildWasm();
}

main();