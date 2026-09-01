/**
 * @file @/pow.worker.js
 * @description Web Worker dédié à la résolution du challenge CPU.
 * Ce script s'exécute sur un thread séparé pour ne pas bloquer l'interface utilisateur.
 */

self.onmessage = async (event) => {
    const { message, target } = event.data;
    let solution = 0;
    const encoder = new TextEncoder();

    // La boucle de calcul intensive est isolée dans ce worker.
    while (true) {
        const currentMessage = `${message}:${solution}`;
        const data = encoder.encode(currentMessage);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        if (BigInt('0x' + hashHex) < target) {
            // Une fois la solution trouvée, on la renvoie au thread principal.
            self.postMessage({ solution });
            return;
        }
        solution++;
    }
};