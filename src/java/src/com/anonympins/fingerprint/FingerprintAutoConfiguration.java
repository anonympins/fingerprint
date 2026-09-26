package com.anonympins.fingerprint;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import java.util.HashMap;
import java.util.Map;

/**
 * Auto-configuration globale et modulaire pour l'activation facile de la librairie.
 * S'active automatiquement lorsque "fingerprint.enabled=true" est présent dans l'application.
 */
@AutoConfiguration
@EnableConfigurationProperties(FingerprintProperties.class)
@ConditionalOnProperty(prefix = "fingerprint", name = "enabled", havingValue = "true")
public class FingerprintAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(IStore.class)
    public IStore fingerprintStore() {
        return new InMemoryStore();
    }

    @Bean
    @ConditionalOnMissingBean(FingerprintEngine.class)
    public FingerprintEngine fingerprintEngine(FingerprintProperties properties, IStore store) {
        Map<String, Object> config = new HashMap<>();
        config.put("thresholds", properties.getThresholds());
        config.put("weights", properties.getWeights());
        config.put("honeypot", properties.getHoneypot());
        config.put("cpu", properties.getCpu());
        config.put("challengeNewDevices", properties.isChallengeNewDevices());
        config.put("challengeTtl", properties.getChallengeTtl());
        config.put("deviceIdCookieMaxAge", properties.getDeviceIdCookieMaxAge());
        config.put("verbose", properties.isVerbose());
        config.put("dryRun", properties.isDryRun());
        config.put("similarityThreshold", properties.getSimilarityThreshold());
        config.put("patterns", properties.getPatterns().toMap());
        config.put("challengePagePath", properties.getChallengePagePath());
        config.put("enableUsefulWork", properties.isEnableUsefulWork());
        config.put("usefulWorkConfigPath", properties.getUsefulWorkConfigPath());
        config.put("usefulWorkConfig", properties.getUsefulWorkConfig());
        config.put("enableProofOfSpace", properties.isEnableProofOfSpace());
        config.put("pospace", properties.getPospace());
        config.put("whitelist", properties.getWhitelist());
        config.put("filterWhitelist", properties.getFilterWhitelist());
        config.put("allowCrossNetworkRoaming", properties.isAllowCrossNetworkRoaming());
        config.put("useAsymmetricTickets", properties.isUseAsymmetricTickets());
        if (properties.getEd25519PrivateKey() != null) {
            config.put("ed25519_private_key", properties.getEd25519PrivateKey());
        }
        if (properties.getEd25519PublicKey() != null) {
            config.put("ed25519_public_key", properties.getEd25519PublicKey());
        }
        config.put("differentialPrivacy", properties.getDifferentialPrivacy().toMap());
        config.put("dpEpsilon", properties.getDpEpsilon());
        return new FingerprintEngine(config, store);
    }

    @Bean
    @ConditionalOnProperty(prefix = "fingerprint.autotuning", name = "enabled", havingValue = "true")
    public AutoTuner fingerprintAutoTuner(FingerprintEngine engine, IStore store, FingerprintProperties properties) {
        AutoTuner tuner = new AutoTuner(engine, store, properties);
        tuner.start(); // Démarrage du thread de planification en tâche de fond
        return tuner;
    }

    /**
     * Configuration automatique pour la pile classique Spring MVC (Servlet-based).
     */
    @Configuration
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(name = "jakarta.servlet.Filter")
    public static class ServletFilterConfiguration {
        @Bean
        public FilterRegistrationBean<FingerprintServletFilter> fingerprintServletFilterRegistration(FingerprintEngine engine) {
            FilterRegistrationBean<FingerprintServletFilter> registration = new FilterRegistrationBean<>();
            registration.setFilter(new FingerprintServletFilter(engine));
            registration.addUrlPatterns("/*");
            registration.setName("fingerprintServletFilter");
            registration.setOrder(1); // Exécuté très tôt dans la chaîne de sécurité
            return registration;
        }
    }

    /**
     * Configuration automatique pour la pile réactive Spring WebFlux.
     */
    @Configuration
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
    @ConditionalOnClass(name = "reactor.netty.Connection")
    @Import({FingerprintWebFluxFilter.class})
    public static class ReactiveFilterConfiguration {
    }
}