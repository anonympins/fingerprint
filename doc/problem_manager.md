# Documentation - ProblemManager & Useful Proof-of-Work (uPoW)

The `ProblemManager` is the core of our protection suite's **Useful Proof-of-Work (uPoW)** system. Rather than imposing useless cryptographic computations (like classic SHA-256 hash mining) on suspicious clients, the engine distributes subtasks of real, useful computations (mathematical optimizations such as TSP, portfolio allocation, or federated training of Machine Learning models).

---

## Key Concepts

1. **Useful Work Dispatching**: When the engine detects a moderate to high suspicion score, it can replace the standard PoW with a unit of useful work via `dispatchWork(suspicionFactor)`.
2. **Difficulty Scaling**: The computational difficulty (iterations, generations) adjusts dynamically via an exponential factor (`scalingFactor`) based on the caller's suspicion.
3. **Anti-Poisoning & Validation**: The server **never** trusts the scores declared by the client. Submitted solutions are recomputed/sampled on the server before being integrated.
4. **State Persistence**: The progress state of problems (Pareto fronts, best solutions) is synchronized and persisted on one of the configured data stores (Redis, MongoDB, SQL, or In-Memory).

---

## 1. Node.js / JavaScript Integration Guide

In Node.js, the `ProblemManager` is asynchronous and relies on a centralized declaration of optimization algorithms via the `library.js` library.

### Initialization and Singleton Retrieval

```javascript
import { getProblemManager } from './problem-manager.js';

// Asynchronous initialization with options and a store (e.g., Redis)
const options = {
    configPath: './config/problems.config.json', // Path to your defined problems
};
const problemManager = await getProblemManager(options, store);
```

### Main Methods

#### Task Dispatcher (`dispatchWork`)
Generates a batch of work adapted to the request's suspicion factor:
```javascript
const suspicionFactor = 0.8; // Between 0.0 and 1.5
const work = problemManager.dispatchWork(suspicionFactor);

if (work) {
    const { problemId, task } = work;
    // Send 'task' to the client (via JSON or injected into the HTML challenge page)
}
```

#### Solution Integration (`integrateSolution`)
Verifies and applies the solution returned by a client:
```javascript
const solutionData = {
    solution: [0, 2, 1, 3], // Example for a TSP
    energy: 324.5          // Declared energy (will be recomputed for validation)
};

await problemManager.integrateSolution(problemId, solutionData);
```

#### Retrieving Results (`getBestSolutions`)
To consume the optimal solutions computed in a distributed manner in your backend:
```javascript
// For a specific problem
const bestTsp = await problemManager.getBestSolutions('tsp_10_cities');
console.log(`Best distance found: ${bestTsp.score} for the path: ${bestTsp.solution}`);

// To get an overview of all single- or multi-objective problems
const allBests = await problemManager.getBestSolutions();
```

---

## 2. PHP Integration Guide

The PHP `ProblemManager` exposes a high-performance synchronous singleton that integrates seamlessly with production JSON configurations.

### Initialization

The manager must be initialized once before it can be used without arguments:
```php
use Anonympins\Fingerprint\ProblemManager;
use Anonympins\Fingerprint\Store\StoreManager;

$store = StoreManager::getStore();
$configPath = __DIR__ . '/config/problems.config.json';

// First call: Initialization
$problemManager = ProblemManager::getInstance($configPath, $store);
```

### Main Methods

#### Dispatching a useful task
```php
$suspicionFactor = 0.5;
$work = $problemManager->dispatchWork($suspicionFactor);

if ($work !== null) {
    $problemId = $work['problemId'];
    $task = $work['task']; // Associative array of the task
}
```

#### Integrating a solution
```php
$solutionData = [
    'solution' => [
        ['x' => 100, 'y' => 100],
        ['x' => 200, 'y' => 200]
    ],
    'energy' => 1500.0
];

$problemManager->integrateSolution($problemId, $solutionData);
```
#### Retrieving Results (getBestSolutions) 
To consume the optimal solutions computed in a distributed manner in your PHP backend:
```php
// For a specific 
$bestTsp = $problemManager->getBestSolutions('tsp_10_cities');
if ($bestTsp !== null) {
    echo "Best distance found: {$bestTsp['score']} for the path: " . json_encode($bestTsp['solution']) . "\n";
}
// To get an overview of all single- or multi-objective problems
$allBests = $problemManager->getBestSolutions();
```

---

## 3. Java Integration Guide (Spring Boot)

The Java implementation supports complex model training abstractions (Machine Learning/federated) and provides a strict base class for anti-poisoning.

### Initialization

```java
import com.anonympins.fingerprint.ProblemManager;
import com.anonympins.fingerprint.IStore;

IStore store = new InMemoryStore(); // Or RedisStore in production
String configPath = "config/problems.config.json";

ProblemManager problemManager = ProblemManager.getInstance(configPath, store);
```

### AI Model Tasks (`UpowModelTask`)

In Java, you can register evaluation or learning tasks (PyTorch/ONNX, TensorFlow) that extend `UpowModelTask`:

```java
import com.anonympins.fingerprint.UpowModelTask;
import java.util.Map;

public class MyClassifierTask extends UpowModelTask {
    public MyClassifierTask(String problemId, String modelPath, Map<String, Object> config) {
        super(problemId, modelPath, config);
    }

    @Override
    public Map<String, Object> dispatchTask(double suspicionFactor) {
        // Prepare a training mini-batch and the current weights
    }

    @Override
    public boolean verifySolution(Map<String, Object> taskContext, Map<String, Object> solution) {
        // Anti-poisoning safeguard (gradient clipping, consistency check)
    }

    @Override
    public void integrateSolution(Map<String, Object> solution) {
        // Apply the validated gradients via a FedAvg algorithm
    }
}

// Register with the ProblemManager
problemManager.registerModelTask(new MyClassifierTask("request_classifier_nn", "models/classifier.onnx", config));
```

### Main Methods

#### Dispatching a task
```java
double suspicionFactor = 1.2;
Map<String, Object> work = problemManager.dispatchWork(suspicionFactor);

if (work != null) {
String problemId = (String) work.get("problemId");
Map<String, Object> task = (Map<String, Object>) work.get("task");
}
```

#### Integrating a solution
```java
Map<String, Object> solutionData = new HashMap<>();
solutionData.put("solution", Arrays.asList(0, 2, 1, 3));
solutionData.put("energy", 324.5);

problemManager.integrateSolution(problemId, solutionData);
```

#### Retrieving Results (`getBestSolutions`)
To consume the optimal solutions computed in a distributed manner in your backend:
```java
// For a specific problem
Map<String, Object> bestTsp = (Map<String, Object>) problemManager.getBestSolutions("tsp_10_cities");
if (bestTsp != null) {
    System.out.println("Best distance found: " + bestTsp.get("score") + " for the path: " + bestTsp.get("solution"));
}

// To get an overview of all single- or multi-objective problems
List<Map<String, Object>> allBests = (List<Map<String, Object>>) problemManager.getBestSolutions();
```

---

## 4. Python Integration Guide

The Python `ProblemManager` provides a flexible and efficient way to integrate uPoW into your applications.

### Initialization

The manager can be initialized with a configuration path and a store implementation.

```python
from fingerprint.problem_manager import ProblemManager
from fingerprint.store import StoreManager

# Assuming StoreManager provides a default store or you can pass one
store = StoreManager.get_store() # Or a specific store like RedisStore()
config_path = './config/problems.config.json'

# Initialize the ProblemManager (likely a singleton or a factory method)
problem_manager = ProblemManager.get_instance(config_path, store)
```

### Main Methods

#### Dispatching a useful task
Generates a batch of work adapted to the request's suspicion factor:
```python
suspicion_factor = 0.7  # Between 0.0 and 1.5
work = problem_manager.dispatch_work(suspicion_factor)

if work:
    problem_id = work['problemId']
    task = work['task']  # Dictionary representing the task
    # Send 'task' to the client
```

#### Integrating a solution
Verifies and applies the solution returned by a client:
```python
solution_data = {
    'solution': [0, 2, 1, 3],  # Example for a TSP
    'energy': 324.5            # Declared energy (will be recomputed for validation)
}

problem_manager.integrate_solution(problem_id, solution_data)
```

#### Retrieving Results (`get_best_solutions`)
To consume the optimal solutions computed in a distributed manner in your backend:
```python
# For a specific problem
best_tsp = problem_manager.get_best_solutions('tsp_10_cities')
print(f"Best distance found: {best_tsp['score']} for the path: {best_tsp['solution']}")

# To get an overview of all single- or multi-objective problems
all_bests = problem_manager.get_best_solutions()
```

---

*To configure custom tasks in your JSON configuration file, please refer to the standard template in `config/problems.config.json`.*