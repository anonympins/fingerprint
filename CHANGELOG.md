## Version 0.2.2 (August 27, 2026)

This version marks a significant evolution from simple Proof-of-Work (PoW) to "Useful Proof-of-Work" (uPoW). Instead of solving arbitrary computational puzzles, clients now contribute to solving complex optimization problems, making the work done to verify a client's legitimacy valuable.

### ✨ New Features

*   **Useful Proof-of-Work (uPoW) System**:
    *   Introduced the `ProblemManager` to oversee long-running optimization problems (e.g., Traveling Salesperson Problem, Portfolio Optimization).
    *   Clients' PoW challenges now consist of running optimization algorithms (like Simulated Annealing or Genetic Algorithms) for a specific number of iterations/generations.
    *   Solutions submitted by clients are integrated back into the system, continuously improving the best-known solution for each problem over time.

*   **Dynamic Problem Configuration**:
    *   The `problems.config.json` file now supports dynamic data generation. You can specify functions like `generate:randomPoints` or `generate:randomAssets` to create new problem instances on startup without manual data entry.

*   **Best Solution API**:
    *   A new method, `fingerprint.getBestSolutions(problemId?)`, has been added. This allows you to retrieve the best solution found so far for a specific problem or for all active problems. This makes the results of the uPoW system accessible and useful.

*   **Re-challenge for High-Suspicion Clients**:
    *   Clients with a very high `suspicionFactor` are now automatically issued a second challenge upon successful completion of the first. This significantly increases the cost of verification for highly suspicious actors without affecting legitimate users.


### 🚀 Improvements

*   **Smarter Challenge Difficulty**:
    *   The difficulty of optimization challenges now scales more intelligently with the client's `suspicionFactor`.
    *   A minimum difficulty has been established for challenges to ensure they are always meaningful, preventing trivial PoW tasks even for low-suspicion clients.
    *   Added a linear "decay" mode as an alternative to exponential scaling. If a `scalingFactor` is not defined for a problem, the difficulty increases linearly, providing a gentler curve for low-suspicion clients.

*   **Data Point Capping**:
    *   Added a `maxDataPoints` option to problem configurations to prevent datasets (e.g., TSP points) from growing indefinitely. This ensures stable performance and memory usage over time. (Thanks, @anonympins!)
*   **Enhanced Test Suite**:
    *   Added comprehensive unit tests for the new `ProblemManager`, ensuring the reliability of problem loading, work dispatching, solution integration, and the new dynamic configuration features.

### Internal & Developer Experience

*   The core logic for managing, dispatching, and updating optimization problems is now encapsulated within `problem-manager.js`.
*   The project now uses `vitest` for running tests, as configured in `package.json`.