package com.anonympins.fingerprint;

import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * Filtre Spring MVC Servlet classique pour évaluer la suspicion des requêtes.
 * Bloque ou challenge les requêtes suspectes avant d'atteindre les contrôleurs.
 */
public class FingerprintServletFilter extends OncePerRequestFilter {
    private final FingerprintEngine engine;

    public FingerprintServletFilter(FingerprintEngine engine) {
        this.engine = engine;
    }

    /**
     * Permet d'accéder à l'instance actuelle de l'engine utilisée par ce middleware.
     *
     * @return L'instance active de FingerprintEngine.
     */
    public FingerprintEngine getEngine() {
        return this.engine;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Extraction des paramètres de requête
        Map<String, Object> queryParams = new HashMap<>();
        request.getParameterMap().forEach((k, v) -> {
            if (v.length == 1) {
                queryParams.put(k, v[0]);
            } else {
                queryParams.put(k, Arrays.asList(v));
            }
        });

        // Extraction des en-têtes
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                headers.put(name.toLowerCase(), request.getHeader(name));
            }
        }

        // Extraction des cookies
        Map<String, String> cookies = new HashMap<>();
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                cookies.put(c.getName(), c.getValue());
            }
        }

        // Résolution de l'adresse IP cliente (avec gestion de proxy)
        String clientIp = request.getHeader("X-Forwarded-For");
        if (clientIp == null || clientIp.isEmpty()) {
            clientIp = request.getRemoteAddr();
        } else {
            clientIp = clientIp.split(",")[0].trim();
        }

        RequestContext context = new RequestContext(
            clientIp,
            request.getRequestURI(),
            headers,
            queryParams,
            null, // Le parsing du body est délégué à la couche applicative
            cookies,
            request.getProtocol()
        );

        Map<String, Object> decision = engine.processRequest(context);

        // Écriture des cookies d'autorisation / d'identité si requis par l'engine
        if (decision.containsKey("cookie")) {
            setServletCookie(response, (Map<String, Object>) decision.get("cookie"));
        }
        if (decision.containsKey("newCookieForResponse")) {
            setServletCookie(response, (Map<String, Object>) decision.get("newCookieForResponse"));
        }

        String action = (String) decision.get("action");
        if ("block".equals(action)) {
            response.setStatus((Integer) decision.getOrDefault("status", 403));
            response.getWriter().write((String) decision.getOrDefault("body", "Forbidden"));
            return;
        } else if ("challenge".equals(action)) {
            response.setStatus((Integer) decision.getOrDefault("status", 403));
            response.setContentType("text/html; charset=utf-8");
            response.getWriter().write((String) decision.getOrDefault("body", ""));
            return;
        } else if ("redirect".equals(action)) {
            response.sendRedirect((String) decision.get("path"));
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void setServletCookie(HttpServletResponse response, Map<String, Object> c) {
        String name = (String) c.get("name");
        String value = (String) c.get("value");
        Cookie cookie = new Cookie(name, value);
        
        Map<String, Object> options = (Map<String, Object>) c.get("options");
        if (options != null) {
            cookie.setPath((String) options.getOrDefault("path", "/"));
            cookie.setHttpOnly((Boolean) options.getOrDefault("httponly", true));
            cookie.setSecure((Boolean) options.getOrDefault("secure", false));
            if (options.containsKey("expires")) {
                long expires = ((Number) options.get("expires")).longValue();
                cookie.setMaxAge((int) ((expires - System.currentTimeMillis()) / 1000));
            }
        }
        response.addCookie(cookie);
    }
}