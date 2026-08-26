/**
 * @file @/optimization.worker.js
 * @description Web Worker générique pour exécuter les algorithmes d'optimisation de la bibliothèque `Optimization`.
 * Ce script s'exécute sur un thread séparé pour ne pas bloquer l'interface utilisateur.
 */

import { parentPort, workerData } from 'worker_threads';
import { Optimization } from './library.js'; // Assurez-vous que le chemin est correct

if (parentPort) {
    parentPort.on('message', async () => { // Le message est vide, on utilise workerData
        const { solverName, solverArgs } = workerData;

        // Gérer les solveurs imbriqués (ex: 'Operators.solvePortfolio')
        const solverFunction = solverName.split('.').reduce((obj, prop) => obj && obj[prop], Optimization);

        if (typeof solverFunction === 'function') {
            try {
                const result = await solverFunction(...solverArgs);
                parentPort.postMessage(result);
            } catch (error) {
                parentPort.postMessage({ error: error.message, stack: error.stack });
            }
        } else {
            parentPort.postMessage({ error: `Solver '${solverName}' not found or is not a function in Optimization library.` });
        }
    });
}