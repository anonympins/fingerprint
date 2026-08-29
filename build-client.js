import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import JavaScriptObfuscator from 'javascript-obfuscator';
import { minify } from 'terser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function buildClientScript() {
  try {
    console.log('Reading client script...');
    const clientScriptPath = join(__dirname, 'fingerprint.client.js');
    const clientScriptContent = await fs.readFile(clientScriptPath, 'utf-8');

    console.log('Obfuscating client script...');
    const obfuscationResult = JavaScriptObfuscator.obfuscate(clientScriptContent, {
      compact: true,
      controlFlowFlattening: true,
      deadCodeInjection: true,
      stringArray: true,
      rotateStringArray: true,
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

buildClientScript();