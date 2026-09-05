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
| `fingerprint_suspicion_score` | Summary | None | Distribution and cumulative sum of suspicion scores calculated for requests. |
| `fingerprint_autotuner_runs_total` | Counter | None | Total number of executions of the genetic auto-tuning module. |
| `fingerprint_autotuner_optimized_config_count` | Gauge | None | Number of times the auto-tuner updated and applied an optimized configuration at runtime. | ---

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

``` $protector = new DirectFingerprint($securityConfig);

if ($_SERVER['REQUEST_URI'] === '/metrics') {
$metricsContext = new RequestContext(/* ... constructor ... */); 
$protector->handleMetricsRequest($metricsContext); // This function handles the response and calls exit()
}
```