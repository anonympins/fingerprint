# Java Integration Guide

This guide details how to integrate and use the `fingerprint` library within a Java ecosystem. 
It supports traditional Servlet-based applications (Spring Boot Web, Tomcat), Reactive APIs (Spring WebFlux), automated threshold optimization (`AutoTuner`), and Netty-level TLS interception.

---

## Prerequisites

* **Java 17+** (Spring Boot 3.x ready)
* The `com.anonympins.fingerprint` dependency.
* Maven or Gradle build system.

---

## Spring Boot Auto-Configuration (Recommended)

The library includes a built-in auto-configuration mechanism. When added to a Spring Boot application, it automatically detects your stack (Servlet or Reactive) and registers the required beans (`FingerprintEngine`, `FingerprintServletFilter`, or `FingerprintWebFluxFilter`) without requiring any manual configuration classes.

### 1. Configuration via Properties

You can customize the thresholds and suspicion weights directly in your `application.yml` or `application.properties` file:

```yaml
fingerprint:
  enabled: true
  thresholds:
    low: 15
    medium: 40
    high: 70
    block: 90
  weights:
    bot-score: 1.5
    inconsistency-score: 0.8
    ipReputationScore: 0.5
    subnetScore: 0.5
  challengeNewDevices: false
  challengeTtl: 300
  deviceIdCookieMaxAge: 2592000000
  similarityThreshold: 0.7
  enableUsefulWork: false
  enableProofOfSpace: false
  pospace:
    sizeMb: 100
    numQueries: 10
    coopTimeout: 15
  autotuning:
    enabled: true
    minDataPoints: 200
    maxDataPoints: 10000
    validationTolerance: 0.15
    interval: 30
    savePath: "config/optimized-security-config.json"
  # Custom storage class reference if needed (defaults to InMemoryStore)
  store-bean-name: "redisStore"
```

---

## Security Profiles

The Java engine supports pre-defined security profiles matching the JS and PHP library equivalents: `balanced` (default), `strict`, `api`, `blog`, and `ecommerce`.

### Usage with Pre-defined Profiles

You can instantiate the engine using a pre-defined profile and optional overrides via `SecurityProfiles`:

```java
import com.anonympins.fingerprint.SecurityProfiles;
import com.anonympins.fingerprint.FingerprintEngine;
import com.anonympins.fingerprint.InMemoryStore;
import java.util.HashMap;
import java.util.Map;

Map<String, Object> overrides = new HashMap<>();
overrides.put("challengeNewDevices", true);

// Create a personalized Strict profile with deep-merged overrides
Map<String, Object> config = SecurityProfiles.createSecurityProfile("strict", overrides);

FingerprintEngine engine = new FingerprintEngine(config, new InMemoryStore());
```

---

## Automated Threshold Tuning (AutoTuner)

The `AutoTuner` class automates the background optimization of suspicion weights, thresholds, and patterns based on real traffic data.

### How it Works
* **Pruning and Anti-Poisoning**: Prunes logs based on expiration or maximum sizes, limiting the impact of Sybil attacks by clustering device behavior.
* **Pareto Frontier Resolution**: Runs a multi-objective genetic algorithm in the background to calculate optimal thresholds and weights.
* **Inertial Smooth Update**: Gradually shifts active configurations using adaptive learning rates, protecting endpoints from abrupt adjustments.
* **Cross-Validation Safeguard**: Evaluates candidates against active traffic data; updates are rejected if they result in an instability or false-positive/negative drift exceeding the `validationTolerance` threshold.

### Setup
If enabled via properties (`fingerprint.autotuning.enabled=true`), the tuner automatically hooks into the Spring lifecycle:

```java
import com.anonympins.fingerprint.AutoTuner;
import com.anonympins.fingerprint.FingerprintEngine;
import com.anonympins.fingerprint.IStore;
import com.anonympins.fingerprint.FingerprintProperties;

// Initialize and start the background execution thread
AutoTuner tuner = new AutoTuner(fingerprintEngine, store, fingerprintProperties);
tuner.start();

// Stop background tuner before shutdown
tuner.stop();
```

---

## 1. Servlet Filter Integration (Spring Boot MVC, Tomcat)

For traditional blocking applications, you can use the `FingerprintServletFilter`. This filter intercepts incoming requests, wraps them in a `RequestContext`, and delegates the decision-making to the `FingerprintEngine`.

*Note: If you are using Spring Boot Auto-Configuration with `fingerprint.enabled: true`, this bean is registered automatically. Manual configuration is only needed for custom setups or non-Boot applications.*

```java
import com.anonympins.fingerprint.FingerprintEngine;
import com.anonympins.fingerprint.FingerprintServletFilter;
import com.anonympins.fingerprint.InMemoryStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SecurityConfig {

    // Our engine instance creation
    @Bean
    public FingerprintEngine fingerprintEngine() {
        Map<String, Object> config = new HashMap<>();
        
        // Setup Custom Thresholds
        Map<String, Object> thresholds = new HashMap<>();
        thresholds.put("low", 15);
        thresholds.put("medium", 40);
        thresholds.put("high", 70);
        thresholds.put("block", 90);
        config.put("thresholds", thresholds);

        // Setup Custom Weights
        Map<String, Object> weights = new HashMap<>();
        weights.put("botScore", 1.5);
        weights.put("inconsistencyScore", 0.8);
        config.put("weights", weights);

        return new FingerprintEngine(config, new InMemoryStore());
    }

    // If you want to override the default behavior
    @Bean
    public FingerprintServletFilter fingerprintFilter(FingerprintEngine engine) {
        return new FingerprintServletFilter(engine);
    }
}
```

---

## 2. Spring WebFlux Integration (Reactive Stream APIs)

For non-blocking reactive stacks, use the `FingerprintWebFluxFilter`. It ensures that computing fingerprints and checking stores do not block reactive event loop threads.

*Note: If you are using Spring Boot Auto-Configuration with `fingerprint.enabled: true`, this filter is registered automatically. Manual configuration is only needed for custom setups or non-Boot applications.*

```java
import com.anonympins.fingerprint.FingerprintEngine;
import com.anonympins.fingerprint.FingerprintWebFluxFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;

@Configuration
public class ReactiveSecurityConfig {

    @Bean
    public FingerprintWebFluxFilter webFluxFilter(FingerprintEngine engine) {
        return new FingerprintWebFluxFilter(engine);
    }
}
```

---

---

## 3. Netty TLS Handshake Interception

To capture JA3, JA4, and raw client hellos directly within Netty before the SSL engine consumes the bytes, you can integrate the `TlsHandshakeInterceptor` into your Netty channel pipeline.

This handler decodes the ClientHello bytes, stores the results in the Netty Channel attributes, and removes itself once processing is complete.

### Netty Pipeline Configuration

```java
import com.anonympins.fingerprint.TlsHandshakeInterceptor;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;

public class MyChannelInitializer extends io.netty.channel.ChannelInitializer<SocketChannel> {
    @Override
    protected void initChannel(SocketChannel ch) {
        ChannelPipeline pipeline = ch.pipeline();
        
        // Add the interceptor at the front of the pipeline (before SSL/TLS handler)
        pipeline.addFirst("tlsHandshakeInterceptor", new TlsHandshakeInterceptor());
        
        // Other handlers (SslHandler, HttpCodec, etc.) follow...
    }
}
```

### Retrieving Handshake Attributes in WebFlux

The `FingerprintWebFluxFilter` automatically attempts to pull these captured TLS attributes from Netty channel attributes if they are not present as headers:

```java
import io.netty.util.AttributeKey;
import reactor.netty.Connection;

// Attributes resolved inside the WebFlux reactive thread context
Mono<Void> filter = chain.filter(exchange).contextWrite(context -> {
    if (context.hasKey(Connection.class)) {
        Connection conn = context.get(Connection.class);
        String ja3 = conn.channel().attr(AttributeKey.<String>valueOf("ja3Hash")).get();
        String ja4 = conn.channel().attr(AttributeKey.<String>valueOf("ja4Hash")).get();
        String raw = conn.channel().attr(AttributeKey.<String>valueOf("ja3Raw")).get();
        
        // Use TLS fingerprints in your request validation logic
    }
    return context;
});
```

---

## 4. Custom Persistent Storage

For production environments, replacing the default in-memory storage (`InMemoryStore`) with a distributed caching layer (like Redis) ensures that states are shared across multiple instances.

You can easily do this by implementing the `IStore` interface:

```java
import com.anonympins.fingerprint.IStore;

public class RedisStore implements IStore {
    // Implement get, set, has, delete using your favorite Redis client (Jedis, Lettuce, Redisson)
}
```

Once implemented, simply pass your custom store to the `FingerprintEngine` constructor:
`new FingerprintEngine(config, new RedisStore())`.