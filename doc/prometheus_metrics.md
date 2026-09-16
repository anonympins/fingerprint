# Additional Documentation: Prometheus Metrics Exposure

This section details usage, security, and available metrics.

## General Operation

The library tracks and stores key indicators regarding requests that were passed, blocked, or challenged, as well as the effectiveness of your Proof-of-Work (PoW) challenges. This data is exposed in the standard raw Prometheus format (via `/metrics`), ready to be scraped by your Prometheus server or Grafana Agent.

## Exposed Prometheus Metrics

Here is the list of metrics collected and exposed by the `MetricsManager`:

| Metric Name | Type | Labels | Description |
 | :--- | :--- | :--- | :--- |
| `fingerprint_requests_total` | Counter | `status="passed"\|"blocked"\|"challenged"\|"whitelisted"\|"dry_run_block"\|"dry_run_challenge"` | Total number of HTTP requests processed by the security engine, broken down by decision status. |
| `fingerprint_challenges_solved_total` | Counter | None | Total number of Proof-of-Work challenges successfully solved by clients. |
| `fingerprint_challenges_failed_total` | Counter | None | Total number of challenge resolution failures (incorrect or expired solutions). |
| `fingerprint_tickets_valid_total` | Counter | None | Total number of valid clearance tickets validated by the engine. |
| `fingerprint_suspicion_score` | Gauge | `action="high_score_subnet_update"\|"passed"` | Real-time observation of suspicion scores calculated for requests under specific actions. |
| `fingerprint_security_weight` | Gauge | `indicator="..."` (e.g., `historyScore`, `rotationScore`) | Active weight assigned to each suspicion indicator in the current configuration. |
| `fingerprint_security_threshold` | Gauge | `level="low"\|"medium"\|"high"\|"block"` | Active score threshold for each enforcement action level. |
| `fingerprint_autotuning_false_positive_rate` | Gauge | None | Current false positive rate calculated by the auto-tuner. |
| `fingerprint_autotuning_false_negative_rate` | Gauge | None | Current false negative rate calculated by the auto-tuner. |
| `fingerprint_threat_intel_received_total` | Counter | `status="accepted"\|"rejected"` | Total number of federated threat intelligence synchronizations received from peers. |
| `fingerprint_threat_intel_broadcast_total` | Counter | None | Total number of threat intelligence alerts broadcasted to federated peers. |

## Integration and Security

Exposing metrics must be strictly secured to prevent attackers from analyzing your detection thresholds in real-time. Always use the `metricsAuthorizationCallback` function.

### Node.js / Express Example

In your Express application, you can define a dedicated `/metrics` route **before** applying the global `powMiddleware` for better performance:

 ```javascript
 import { handleMetricsRequest } from '@anonympins/fingerprint';
 
 const securityConfig = {
   metricsAuthorizationCallback: async (context) => {
     // Example: Allow only the Prometheus server's local IP address
     const trustedIps = ['127.0.0.1', '::1', '10.0.0.50']; // Your Prometheus server IP
     if (trustedIps.includes(context.clientIp)) {
       return true; 
     }
 
     // Or validate a secret header token (e.g., X-Metrics-Token)
     if (context.headers['x-metrics-token'] === 'your_very_secret_prometheus_token') {
       return true; 
     }
 
     return false; // Deny by default
   }
 };
 
 app.get('/metrics', async (req, res) => {
   await handleMetricsRequest(req, res, securityConfig);
 });
 ```

### PHP Example (Direct Integration)

In PHP, you can intercept the `/metrics` request at the very beginning of your controller or main routing file:

 ```php
 use Anonympins\Fingerprint\DirectFingerprint;
 use Anonympins\Fingerprint\RequestContext;
 
 $securityConfig = [
   'metricsAuthorizationCallback' => function (RequestContext $context) {
     // Allow only local requests or those with a token
     return $context->clientIp === '127.0.0.1'
       || $context->getHeader('X-Metrics-Token') === 'your_very_secret_prometheus_token'; 
   }
 ];
 
 $protector = new DirectFingerprint($securityConfig);
 
 if ($_SERVER['REQUEST_URI'] === '/metrics') {
     $metricsContext = new RequestContext(/* ... constructor ... */); 
     $protector->handleMetricsRequest($metricsContext); // This function handles the response and calls exit()
 }
 ```

## Programmatic Metrics Retrieval (`getMetric`)

Beyond exposing HTTP endpoints, you can query active indicators and counters programmatically directly from your backend code. This is useful for writing custom dashboards, creating internal alerts, or performing health checks.

### Node.js / JavaScript Example

In Node.js, import `getMetric` from the package to retrieve live metrics:

 ```javascript
 import { getMetric } from '@anonympins/fingerprint';
 
 // 1. Retrieve a dynamic counter (e.g., total requests)
 const requestsStats = getMetric('requests_total');
 console.log(requestsStats);
 // Output: Map(2) { 'status="passed"' => 143, 'status="challenged"' => 12 }
 
 // 2. Query active weights (requires the security configuration object)
 const activeWeights = getMetric('security_weight', securityConfig);
 const historyWeight = activeWeights.get('historyScore');
 console.log(`Active history weight: ${historyWeight}`);
 // Output: Active history weight: 0.3
 
 // 3. Query thresholds
 const activeThresholds = getMetric('security_threshold', securityConfig);
 console.log(activeThresholds);
 // Output: Map(4) { 'low' => 20, 'medium' => 45, 'high' => 75, 'block' => 95 }
 ```

### PHP Example

In PHP, use the static `MetricsManager::getMetric` method to query active metrics:

 ```php
 use Anonympins\Fingerprint\Utils\MetricsManager;
 
 // 1. Retrieve a dynamic counter (e.g., total requests)
 $requestsStats = MetricsManager::getMetric('requests_total');
 print_r($requestsStats);
 /*
 Array
 (
     [status="passed"] => 143
     [status="challenged"] => 12
 )
 */
 
 // 2. Query active weights
 $activeWeights = MetricsManager::getMetric('security_weight', $securityConfig);
 echo "Active history weight: " . ($activeWeights['historyScore'] ?? 0.0) . "\n";
 // Output: Active history weight: 0.3
 
 // 3. Query active thresholds
 $activeThresholds = MetricsManager::getMetric('security_threshold', $securityConfig);
 print_r($activeThresholds);
 /*
 Array
 (
     [low] => 20
     [medium] => 45
     [high] => 75
     [block] => 95
 )
 */
 ```

### Java Example

In Spring Boot or standard Java environments, retrieve the metrics from the `RequestUtils` helper:

 ```java
 import com.anonympins.fingerprint.utils.RequestUtils;
 import com.anonympins.fingerprint.utils.MetricsManager;
 import java.util.Map;
 
 // 1. Retrieve a dynamic counter (e.g., total requests)
 Map<String, Double> requestsStats = MetricsManager.getMetric("requests_total", securityConfig);
 System.out.println("Passed requests: " + requestsStats.getOrDefault("status=\"passed\"", 0.0));
 // Output: Passed requests: 143.0
 
 // 2. Query active weights
 Map<String, Double> activeWeights = MetricsManager.getMetric("security_weight", securityConfig);
 System.out.println("Active history weight: " + activeWeights.get("historyScore"));
 // Output: Active history weight: 0.3
 
 // 3. Query active thresholds
 Map<String, Double> activeThresholds = MetricsManager.getMetric("security_threshold", securityConfig);
 System.out.println("Low threshold: " + activeThresholds.get("low"));
 // Output: Low threshold: 20.0
 ```