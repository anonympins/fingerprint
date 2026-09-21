/**
 * @file @/pow.worker.js
 * @description Web Worker dédié à la résolution du challenge CPU.
 * Ce script s'exécute sur un thread séparé pour ne pas bloquer l'interface utilisateur.
 */

self.onmessage = async (event) => {
    const { message, baseBlock, target } = event.data;
    const cpuTarget = BigInt(target);
    let solution = 0;
    const encoder = new TextEncoder();
    if (baseBlock) {
        // Mode solveCpuTargetInline (Uint8Array base block)
        const blockArray = new Uint8Array(baseBlock);
        while (true) {
            const solutionBytes = encoder.encode(String(solution));
            const finalBlock = new Uint8Array(blockArray.length + solutionBytes.length);
            finalBlock.set(blockArray);
            finalBlock.set(solutionBytes, blockArray.length);
            const hashBuffer = await crypto.subtle.digest('SHA-256', finalBlock);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            if (BigInt('0x' + hashHex) < cpuTarget) {
                self.postMessage({ type: 'success', solution });
                return;
            }
            solution++;
            if (solution % 25000 === 0) {
                self.postMessage({ type: 'progress', solution });
            }
        }
    } else {
        // Mode solveCpuTarget standard/legacy (Message string)
        while (true) {
            const currentMessage = `${message}:${solution}`;
            const data = encoder.encode(currentMessage);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

            if (BigInt('0x' + hashHex) < cpuTarget) {
                self.postMessage({ solution });
                return;
            }
            solution++;
        }
    }
};