import { parentPort } from 'node:worker_threads';
import JavaScriptObfuscator from 'javascript-obfuscator';

if (parentPort) {
    parentPort.on('message', (workerData) => {
        const { jsCode, seed } = workerData;
        try {
            const obfuscationResult = JavaScriptObfuscator.obfuscate(jsCode, {
                compact: true,
                controlFlowFlattening: true,
                deadCodeInjection: true,
                stringArray: true,
                stringArrayRotate: true,
                stringArrayShuffle: true,
                seed: Math.abs(seed),
                selfDefending: true,
            });
            parentPort.postMessage({ obfuscatedCode: obfuscationResult.getObfuscatedCode() });
        } catch (error) {
            parentPort.postMessage({ error: error.message, stack: error.stack });
        }
    });
}