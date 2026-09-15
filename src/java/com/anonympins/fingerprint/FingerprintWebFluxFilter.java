package com.anonympins.fingerprint;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;

/**
 * Filtre WebFlux réactif pour capturer les empreintes JA3/JA4 depuis les en-têtes HTTP
 * injectés par un reverse proxy (ex: Nginx, Envoy).
 * 
 * Les empreintes sont stockées dans les attributs de l'échange WebFlux (ServerWebExchange),
 * équivalent réactif des attributs de requête Servlet.
 */
@Component
public class FingerprintWebFluxFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.deferContextual(contextView -> {
            // Extraction des en-têtes réactifs (Proxy)
            String ja3Hash = exchange.getRequest().getHeaders().getFirst("X-JA3-Hash");
            String ja4Hash = exchange.getRequest().getHeaders().getFirst("X-JA4-Hash");
            String ja3Raw = exchange.getRequest().getHeaders().getFirst("X-JA3-Raw");

            // Si non présents dans les en-têtes, extraction depuis les attributs du canal Netty (couche TLS locale)
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

            // Stockage dans les attributs de l'échange ( exchange.getAttributes() )
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