# Documentation additionnelle : Exposition des métriques Prometheus

Cette section détaille l'utilisation, la sécurisation et les métriques disponibles.

## Fonctionnement général

La bibliothèque commence à suivre et à stocker des indicateurs clés sur les requêtes passées, bloquées, challengées, ainsi que sur l'efficacité de vos défis de Proof-of-Work (PoW). Ces données sont exposées au format brut standard Prometheus (via `/metrics`), prêtes à être collectées (scraped) par votre serveur Prometheus ou Grafana Agent.

## Métriques Prometheus exposées

Voici la liste des métriques collectées et exposées par le `MetricsManager` :

| Nom de la métrique | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `fingerprint_requests_total` | Counter | `status="passed"\|"blocked"\|"challenged"\|"whitelisted"\|"dry_run_block"\|"dry_run_challenge"` | Nombre total de requêtes HTTP traitées par le moteur de sécurité, ventilées par statut de décision. |
| `fingerprint_challenges_solved_total` | Counter | Aucun | Nombre total de challenges Proof-of-Work résolus avec succès par les clients. |
| `fingerprint_challenges_failed_total` | Counter | Aucun | Nombre total d'échecs de résolution de challenges (solutions incorrectes ou expirées). |
| `fingerprint_suspicion_score` | Summary | Aucun | Distribution et somme cumulée des scores de suspicion calculés pour les requêtes. |
| `fingerprint_autotuner_runs_total` | Counter | Aucun | Nombre total d'exécutions du module d'auto-tuning génétique. |
| `fingerprint_autotuner_optimized_config_count` | Gauge | Aucun | Nombre de fois où l'auto-tuner a mis à jour et appliqué une configuration optimisée en direct. |

---

## Intégration et Sécurisation

L'exposition des métriques doit être strictement sécurisée pour éviter que des attaquants n'analysent vos seuils de détection en temps réel. Utilisez toujours la fonction `metricsAuthorizationCallback`.

### Exemple Node.js / Express

Dans votre application Express, vous pouvez déclarer une route dédiée `/metrics` **avant** d'appliquer le middleware global `powMiddleware` pour de meilleures performances :

```javascript
import { handleMetricsRequest } from '@anonympins/fingerprint';

const securityConfig = {
    metricsAuthorizationCallback: async (context) => {
        // Exemple : Autoriser uniquement l'adresse IP locale du serveur Prometheus
        const trustedIps = ['127.0.0.1', '::1', '10.0.0.50']; // IP de votre serveur Prometheus
        if (trustedIps.includes(context.clientIp)) {
            return true;
        }
        
        // Ou valider un token secret d'en-tête (ex: X-Metrics-Token)
        if (context.headers['x-metrics-token'] === 'votre_token_tres_secret_prometheus') {
            return true;
        }

        return false; // Refuser par défaut
    }
};

app.get('/metrics', async (req, res) => {
    await handleMetricsRequest(req, res, securityConfig);
});
```

### Exemple PHP (Intégration directe)

En PHP, vous pouvez intercepter la requête `/metrics` au tout début de votre contrôleur ou fichier de routage principal :

```php
use Anonympins\Fingerprint\DirectFingerprint;
use Anonympins\Fingerprint\RequestContext;

$securityConfig = [
    'metricsAuthorizationCallback' => function (RequestContext $context) {
        // Autoriser uniquement les requêtes locales ou munies d'un token
        return $context->clientIp === '127.0.0.1' 
            || $context->getHeader('X-Metrics-Token') === 'votre_token_tres_secret_prometheus';
    }
];

$protector = new DirectFingerprint($securityConfig);

if ($_SERVER['REQUEST_URI'] === '/metrics') {
    $metricsContext = new RequestContext(/* ... constructeur ... */);
    $protector->handleMetricsRequest($metricsContext); // Cette fonction gère l'envoi et appelle exit()
}
```