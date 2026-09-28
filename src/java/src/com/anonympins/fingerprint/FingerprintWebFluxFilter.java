package com.anonympins.fingerprint;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;

/**
 * Reactive WebFlux filter to capture JA3/JA4 fingerprints from HTTP headers
 * injected by a reverse proxy (e.g. Nginx, Envoy).
 * 
 * Fingerprints are stored in the WebFlux exchange attributes (ServerWebExchange),
 * the reactive equivalent of Servlet request attributes.
 */
@Component
public class FingerprintWebFluxFilter implements WebFilter {

    private final FingerprintEngine engine;

    public FingerprintWebFluxFilter(FingerprintEngine engine) {
        this.engine = engine;
    }

    /**
     * Provides access to the current engine instance used by this middleware.
     *
     * @return The active FingerprintEngine instance.
     */
    public FingerprintEngine getEngine() {
        return this.engine;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.deferContextual(contextView -> {
            // Reactive header extraction (Proxy)
            String ja3Hash = exchange.getRequest().getHeaders().getFirst("X-JA3-Hash");
            String ja4Hash = exchange.getRequest().getHeaders().getFirst("X-JA4-Hash");
            String ja3Raw = exchange.getRequest().getHeaders().getFirst("X-JA3-Raw");

            // If not present in headers, extract from Netty channel attributes (local TLS layer)
            if (ja3Hash == null || ja4Hash == null || ja3Raw == null) {
                if (contextView.hasKey(Connection.class)) {
                    Connection conn = contextView.get(Connection.class);

                    if (ja3Hash == null) {
                        ja3Hash = conn.channel().attr(TlsHandshakeInterceptor.JA3_HASH_KEY).get();
                    }
                    if (ja4Hash == null) {
                        ja4Hash = conn.channel().attr(TlsHandshakeInterceptor.JA4_HASH_KEY).get();
                    }
                    if (ja3Raw == null) {
                        ja3Raw = conn.channel().attr(TlsHandshakeInterceptor.JA3_RAW_KEY).get();
                    }
                }
            }

            // Store in exchange attributes ( exchange.getAttributes() )
            if (ja3Hash != null) {
                exchange.getAttributes().put("ja3Hash", ja3Hash);
            }
            if (ja4Hash != null) {
                exchange.getAttributes().put("ja4Hash", ja4Hash);
            }
            if (ja3Raw != null) {
                exchange.getAttributes().put("ja3Raw", ja3Raw);
            }

            return chain.filter(exchange);
        });
    }
}