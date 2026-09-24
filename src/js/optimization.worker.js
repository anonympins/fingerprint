/**
 * @file @/optimization.worker.js
 * @description Generic Web Worker running optimization routines from `Optimization`.
 * Runs on a dedicated worker thread to maintain main thread responsiveness.
 */

import {parentPort, workerData} from 'worker_threads';
import {Optimization} from './library.js';

if (parentPort) {
    parentPort.on('message', async () => { // Empty message payload; parameters loaded via workerData
        const { solverName, solverArgs } = workerData;

        // Resolve nested solver paths (e.g. 'Operators.solvePortfolio')
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