# Java Integration Guide

This guide details how to integrate and use the `fingerprint` library within a Java ecosystem, supporting both traditional Servlet-based applications (Spring Boot Web, Tomcat) and modern Reactive APIs (Spring WebFlux).

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
  # Custom storage class reference if needed (defaults to InMemoryStore)
  store-bean-name: "redisStore"
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

## 3. Custom Persistent Storage

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