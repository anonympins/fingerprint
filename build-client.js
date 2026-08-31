import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { exec } from 'node:child_process';
import JavaScriptObfuscator from 'javascript-obfuscator';
import { minify } from 'terser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Tente d'exécuter la commande de build pour le module WASM.
 * Ne bloque pas le build si la commande échoue (ex: em++ non trouvé).
 */
function buildWasm() {
  return new Promise((resolve) => {
    console.log('Attempting to build WASM module (optional)...');
    const command = "em++ src/cpp/main.cpp src/cpp/utils.cpp -o public/fp.js -s WASM=1 -s MODULARIZE=1 -s EXPORT_NAME='createFingerprintModule' -s \"EXPORTED_FUNCTIONS=['_hash_string']\" -O3 --no-entry";
    
    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.warn('WASM build failed (this is optional and can be ignored):', stderr);
      } else {
        console.log('WASM module built successfully.');
      }
      resolve(); // Toujours résoudre la promesse pour ne pas bloquer le build principal.
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
      controlFlowFlattening: true, // Aplatit le flux de contrôle
      deadCodeInjection: true, // Injecte du code mort
      stringArray: true,
      stringArrayRotate: true, // Fait tourner le tableau de chaînes
      stringArrayShuffle: true, // Mélange le tableau de chaînes
      // L'utilisation d'une graine (seed) de 0 signifie que l'obfuscation sera déterministe
      // pour une même entrée. Pour une obfuscation unique à chaque build, on peut utiliser
      // une graine aléatoire, par exemple : seed: Math.random()
      seed: Math.random(),
      selfDefending: true,
    });

    const obfuscatedCode = obfuscationResult.getObfuscatedCode();

    console.log('Writing obfuscated script to fingerprint.client.obfuscated.js...');
    await fs.writeFile(join(__dirname, 'fingerprint.client.obfuscated.js'), obfuscatedCode);

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