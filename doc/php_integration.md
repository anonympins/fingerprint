# PHP Integration Guide

This guide details how to integrate and optimize the `fingerprint` library in your PHP applications, from simple direct scripts to advanced server configurations.

## Prerequisites

* **PHP 8.0+**
* The **BCMath** extension (`php-bcmath`) is required.
* **Composer** for package management.
* The **GMP** extension (`php-gmp`) is highly recommended for performance. If not available, the library will fall back to a slower BCMath-based implementation for cryptographic operations.

 ---

## Basic Direct Integration (No Framework)

You can protect your application's entry point (e.g., `index.php`) by calling the `protect()` method at the very beginning of your script.

 ```php
 <?php
 
 declare(strict_types=1);
 
 require_once __DIR__ . '/vendor/autoload.php';
 
 use Anonympins\Fingerprint\Config\SecurityProfiles;
 use Anonympins\Fingerprint\DirectFingerprint;
 
 // 1. Choose a security profile and customize it if necessary.
 $securityConfig = SecurityProfiles::createSecurityProfile('balanced', [
     'verbose' => true, // Enable verbose mode for development
 ]);
 
 // 2. Create an instance of the DirectFingerprint protector.
 $protector = new DirectFingerprint($securityConfig);
 
 // 3. Protect the script.
 // This method will analyze the request. If it's suspicious, it will
 // send a challenge or block response and then call `exit()`.
 $fingerprint = $protector->protect();
 
 // --- If the script continues, the request was allowed ---
 $score = $fingerprint['score'] ?? 0;
 
 header('Content-Type: text/html; charset=utf-8');
 echo "<h1>Welcome to the protected page!</h1>";
 echo "<p>Your suspicion score was: " . round($score, 2) . "</p>";
 ```
 
---

## TLS Fingerprinting (JA3/JA4) with Nginx and Apache

Unlike Node.js, which can directly inspect the TLS handshake, a standard PHP environment (such as PHP-FPM) runs behind a web server (Nginx, Apache) that terminates the TLS connection. To enable robust TLS fingerprinting in PHP, you must configure your web server to extract the fingerprint and pass it to PHP via HTTP headers.

The library automatically looks for:
* `X-JA3-Hash`
* `X-JA4-Hash`

### Configuration with Nginx

Requires your Nginx instance to be compiled with the `ngx_http_ssl_ja3_module` module.

 ```nginx
 http {
     map $ssl_ja3_hash $ja3_hash {
         default $ssl_ja3_hash; 
     }
 
     server {
         listen 443 ssl http2; 
         server_name yourdomain.com; 
 
         ssl_certificate /path/to/your/fullchain.pem; 
         ssl_certificate_key /path/to/your/privkey.pem; 
 
         location / {
             try_files $uri $uri/ /index.php?$query_string; 
         }
 
         location ~ \.php$ {
             include fastcgi_params; 
             fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; 
             fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; 
             
             # Pass the JA3 fingerprint as a FastCGI parameter. 
             fastcgi_param HTTP_X_JA3_HASH $ja3_hash; 
         }
     }
 }
 ```

### Configuration with Apache

Using the third-party module `mod_ssl_ja3`, you can add the JA3 header in your Virtual Host configuration:

 ```apache
 <VirtualHost *:443>
     ServerName yourdomain.com
     # ... SSL configuration ...
 
     # The JA3_HASH environment variable is provided by mod_ssl_ja3
     RequestHeader set X-JA3-Hash "%{JA3_HASH}e"
 
     # ... your PHP application configuration ...
 </VirtualHost>
 ```
 
---

## Why can't PHP calculate TLS fingerprints natively?

Unlike Node.js, which often acts as a direct web server terminating TLS connections itself and exposing socket metadata (like `socket.clientHello`), standard PHP (PHP-FPM, Apache `mod_php`) runs behind a web server or a reverse proxy.

1. **TLS Termination**: Your web server (Nginx, Apache) or CDN (Cloudflare) terminates the TLS connection. It performs the cryptographic handshake and decrypts the traffic.
2. **FastCGI / SAPI Abstraction**: The web server forwards a clean, plain-text HTTP request to PHP. By the time PHP gets the request, the raw **TLS Client Hello** packet (which contains the cipher suites and extensions order needed to compute JA3/JA4) has already been processed and discarded.

### Alternatives to compiling server modules:
If you cannot install custom modules like `ngx_http_ssl_ja3_module` on your server, you can use one of the following approaches:

* **Cloudflare**: Cloudflare automatically calculates the JA3 signature and forwards it in the `CF-JA3-Sig` header. You can map this header to `X-JA3-Hash` in your configuration.
* **AWS Cloudfront**: Cloudfront can be configured to forward TLS client handshakes headers.
* **PHP Application Servers (Swoole / ReactPHP / Workerman)**: By bypassing standard reverse proxies and handling sockets directly, you can use the built-in native `TLSClientHelloParser` to intercept the binary handshake directly inside PHP's Event Loop.

### Native TLS Extraction inside PHP Event Loops (e.g., Workerman)

If you run a raw TCP worker, you can peek at the first incoming bytes of the stream connection (the raw **Client Hello** payload) before upgrading the connection stream to SSL/TLS.

Here is a concrete example using the native `TLSClientHelloParser` within a Workerman connection listener:

```php
<?php

use Workerman\Worker;
use Workerman\Connection\TcpConnection;
use Anonympins\Fingerprint\Utils\TLSClientHelloParser;

$worker = new Worker('tcp://0.0.0.0:443');

$worker->onConnect = function(TcpConnection $connection) {
    // Intercept the first chunk of data (the raw TLS handshake)
    $connection->onMessage = function(TcpConnection $connection, $rawData) {
        // Parse the binary payload to calculate JA3 natively in PHP
        $tlsData = TLSClientHelloParser::parse($rawData);
        if ($tlsData) {
            // Attach the fingerprint directly to the connection context
            $connection->ja3Hash = $tlsData['ja3_hash'];
        }

        // Clear the temporary plain-text parser callback
        $connection->onMessage = null;

        // Dynamically upgrade the socket transport layer to SSL (initiates cryptographic handshake)
        $connection->transport = 'ssl';

        // Bind your final application logic/HTTP router
        $connection->onMessage = function($conn, $httpPayload) {
            // $conn->ja3Hash is available here for real-time security score checks!
        };

        // Pipe back the buffered bytes so the SSL engine can consume the Client Hello
        $connection->consumeFirstLocalBuffer($rawData);
    };
};

Worker::runAll();
```

---

## Exposing Prometheus Metrics

You can expose a Prometheus-compatible endpoint. **It is CRUCIAL to secure this endpoint** using a `metricsAuthorizationCallback` in your `securityConfig`.

 ```php
 <?php
 
 $securityConfig['metricsAuthorizationCallback'] = function (\Anonympins\Fingerprint\RequestContext $context) {
     // Example: Allow only from localhost or with a specific API Key
     if ($context->clientIp === '127.0.0.1' || $context->clientIp === '::1') {
         return true; 
     }
 
     if (($context->headers['X-Metrics-API-Key'] ?? '') === 'your-secret-api-key') {
         return true; 
     }
 
     return false; // Deny by default
 };
 
 $protector = new DirectFingerprint($securityConfig);
 
 // Handle the /metrics route
 if (isset($_GET['metrics'])) {
     $metricsContext = new \Anonympins\Fingerprint\RequestContext(
         $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
         parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '/',
         function_exists('getallheaders') ? getallheaders() : [],
         $_GET,
         $_POST ?: json_decode(file_get_contents('php://input'), true),
         $_COOKIE,
         $_SERVER['SERVER_PROTOCOL'] ?? '1.1'
     );
     $protector->handleMetricsRequest($metricsContext);
     // handleMetricsRequest will output and call exit() automatically
 }
 ```

## Next Steps

* See Full Configuration Options to discover all options you can tune.
* See Client Side Integration to enable proactive browser challenges and behavioral trackers.
