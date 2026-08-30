<?php

 declare(strict_types=1);

 namespace Anonympins\Fingerprint;

 use Anonympins\Fingerprint\Config\SecurityProfiles;
 use Anonympins\Fingerprint\Store\StoreManager;
 use Anonympins\Fingerprint\Challenge\ChallengeUtils;
 use Anonympins\Fingerprint\Utils\BlockList;

 /**
  * Le moteur principal de la bibliothèque de fingerprinting.
  * Orchestre l'identification, le calcul de suspicion et la gestion des challenges.
  */
 class FingerprintEngine
 {
     private array $securityConfig;
     private bool $isProduction;
     private BlockList $allowlist;
     private bool $verbose;

     public function __construct(array $securityConfig)
     {
         $this->isProduction = ($_ENV['APP_ENV'] ?? getenv('APP_ENV')) === 'production';
         $this->securityConfig = $securityConfig;
         $this->allowlist = $this->buildAllowlist();
         $this->validateConfig($securityConfig);
         $this->verbose = $securityConfig['verbose'] ?? false;
     }

     private function validateConfig(array $config): void
     {
         if (empty($config)) {
             $this->log('Warning: No securityConfig provided. Using default behaviors.', [], 'warn');
             return;
         }

         $knownKeys = [
             'weights', 'thresholds', 'cpu', 'ticketMaxAge', 'challengeTtl',
             'deviceIdCookieMaxAge', 'challengePagePath', 'verbose', 'patterns',
             'honeypot', 'threatIntel', 'whitelist', 'isStaticResource', 'isApiRequest', 'logger',
             'autotuning', 'enableUsefulWork', 'usefulWorkConfigPath', 'challengeNewDevices', 'graphql_operation_allowlist',
             'similarityThreshold', 'summary', 'description'
         ];

         if (empty($config['weights'])) {
             $this->log('Warning: `securityConfig.weights` is not defined. Suspicion scores will be 0.', [], 'warn');
         }
         if (empty($config['thresholds'])) {
             $this->log('Warning: `securityConfig.thresholds` is not defined. Challenges may not be issued correctly.', [], 'warn');
         }

         foreach (array_keys($config) as $key) {
             if (!in_array($key, $knownKeys, true)) {
                 $this->log("Warning: Unknown key '{$key}' found in securityConfig. This might be a typo.", [], 'warn');
             }
         }
     }

     private function log(string $message, array $data = [], string $level = 'info'): void
     {
         if ($this->verbose) {
             $logMessage = "[FingerprintEngine] {$message}";
             if (!empty($data)) {
                 $logMessage .= ' ' . json_encode($data);
             }
             error_log($logMessage);
         }
     }

     public function calculateFinalScore(array $suspicionVector): float
     {
         $weights = $this->securityConfig['weights'] ?? [];
         if (empty($weights)) {
             return 0.0;
         }

         $score = 0.0;
         foreach ($weights as $key => $weight) {
             $score += ($suspicionVector[$key] ?? 0) * $weight;
         }

         return min(100.0, $score);
     }

     private function buildAllowlist(): BlockList
     {
         $blockList = new BlockList();
         $whitelistRules = $this->securityConfig['whitelist'] ?? [];

         $allowlistRule = null;
         foreach ($whitelistRules as $rule) {
             if (($rule['type'] ?? '') === 'allowlist') {
                 $allowlistRule = $rule;
                 break;
             }
         }

         if (empty($allowlistRule['entries'])) {
             return $blockList;
         }

         foreach ($allowlistRule['entries'] as $entry) {
             $blockList->add($entry);
         }
         return $blockList;
     }

     private function isIpInAllowlist(string $clientIp): bool
     {
         return $this->allowlist->check($clientIp);
     }

     private function isPathInAllowlist(string $requestPath): bool
     {
         $whitelistRules = $this->securityConfig['whitelist'] ?? [];
         $pathAllowlistRule = null;
         foreach ($whitelistRules as $rule) {
             if (($rule['type'] ?? '') === 'path_allowlist') {
                 $pathAllowlistRule = $rule;
                 break;
             }
         }

         if (empty($pathAllowlistRule['entries'])) {
             return false;
         }

         foreach ($pathAllowlistRule['entries'] as $entry) {
             if (str_ends_with($entry, '*')) {
                 $base = substr($entry, 0, -1);
                 if (str_starts_with($requestPath, $base)) {
                     return true;
                 }
             } elseif ($requestPath === $entry) {
                 return true;
             }
         }

         return false;
     }

     /**
      * Vérifie si une requête doit être exemptée en raison d'une règle de liste blanche.
      */
     private function checkAllowlists(RequestContext $context): bool
     {
         if ($this->isIpInAllowlist($context->clientIp)) {
             $this->log('IP in allowlist - allowing request', ['clientIp' => $context->clientIp]);
             return true;
         }
         if ($this->isPathInAllowlist($context->path)) {
             $this->log('Path in allowlist - allowing request', ['path' => $context->path]);
             return true;
         }
         // TODO: Implémenter les autres vérifications de liste blanche (hostname, bot, etc.)
         return false;
     }

     /**
      * @return array{deviceId: string, deviceData: ?array, newCookie: ?array, cookieDroppingScore: int}
      */
     private function resolveRequestIdentity(RequestContext $context): array
     {
         $store = StoreManager::getStore();
         $existingDeviceId = $context->cookies['device_id'] ?? null;
         $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
         $pendingCookieTtl = 120; // 2 minutes

         $cookieDroppingScore = 0;
         $deviceId = $existingDeviceId;
         $deviceData = null;
         $newCookie = null;

         if ($deviceId) {
             $deviceData = $store->get("device:{$deviceId}");
         }

         if (!$deviceData) {
             // Nouvel utilisateur ou cookie perdu/invalide
             $pendingDeviceId = $store->get("pending_cookie:{$context->clientIp}");
             if ($pendingDeviceId) {
                 $cookieDroppingScore = 100; // Forte pénalité
                 $store->delete("pending_cookie:{$context->clientIp}");
             }

             $deviceId = bin2hex(random_bytes(16)); // UUID-like

             $newCookie = [
                 'name' => 'device_id',
                 'value' => $deviceId,
                 'options' => [
                     'httponly' => true,
                     'secure' => $this->isProduction,
                     'samesite' => 'Strict',
                     'path' => '/',
                 ]
             ];
             if (isset($this->securityConfig['deviceIdCookieMaxAge'])) {
                 $newCookie['options']['expires'] = time() + ($this->securityConfig['deviceIdCookieMaxAge'] / 1000);
             }

             $store->set("pending_cookie:{$context->clientIp}", $deviceId, $pendingCookieTtl);

             $deviceData = [
                 'initialDeviceHash' => $currentDeviceHash,
                 'ips' => [$context->clientIp], // Utiliser un tableau simple
                 'requestHistory' => [],
                 'lastUpdate' => time() * 1000,
                 'lastFpHash' => $currentDeviceHash,
                 'lastChangeTimestamp' => 0,
                 'rapidChangeCount' => 0,
                 'highScoreCount' => 0,
                 'lastHighScoreTimestamp' => 0,
             ];
             // L'écriture se fera plus tard dans getSuspicionVector
         }

         return [
             'deviceId' => $deviceId,
             'deviceData' => $deviceData,
             'newCookie' => $newCookie,
             'cookieDroppingScore' => $cookieDroppingScore
         ];
     }

     /**
      * @return array<string, float>
      */
     public function getSuspicionVector(RequestContext $context): array
     {
         $store = StoreManager::getStore();
         $identity = $this->resolveRequestIdentity($context);
         $deviceData = $identity['deviceData'];
         $deviceId = $identity['deviceId'];
 
         // Si un nouveau cookie doit être défini, on le stocke temporairement dans le contexte
         // pour que le code appelant puisse le gérer.
         if ($identity['newCookie']) {
             // Cette propriété n'est pas standard, on la préfixe pour éviter les conflits.
             $context->newCookieForResponse = $identity['newCookie'];
         }
 
         // Nettoyage périodique des données de l'appareil
         if ((time() * 1000) - ($deviceData['lastUpdate'] ?? 0) > 10 * 60 * 1000) { // 10 minutes
             $deviceData['ips'] = [];
             $deviceData['rapidChangeCount'] = 0;
         }
         $deviceData['lastUpdate'] = time() * 1000;
 
         // --- Calcul des différents scores de suspicion ---

         // Score d'incohérence du fingerprint
         $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
         $consistencyScore = FingerprintBuilder::compare($deviceData['initialDeviceHash'] ?? null, $currentDeviceHash);
         $inconsistencyScore = min(100.0, max(0.0, (1 - $consistencyScore) * 200));
         if ($consistencyScore < 0.7) {
             $inconsistencyScore = 100.0;
         }

         // Scores comportementaux (rotation d'IP et de fingerprint)
         // Note: La logique complexe de `getBehavioralIndicators` et `getRequestPatternScore`
         // reste à porter et à intégrer ici, car elle modifie l'état `$deviceData`.
         // Pour l'instant, nous appelons les stubs.
         $behavioral = Utils\RequestUtils::getBehavioralIndicators($context, $deviceData);

         // Score des anomalies d'en-têtes
         $headerAnomalies = Utils\RequestUtils::getHeaderAnomalies($context);

         // Score de spoofing TLS
         $tlsSpoofing = Utils\RequestUtils::getTlsSpoofingScore($context);

         // Score d'incohérence temporelle (attaque par rejeu)
         $timeInconsistency = Utils\RequestUtils::getTimeInconsistencyScore($context);

         // Score des incohérences entre couches (client vs serveur)
         $crossLayerInconsistency = Utils\RequestUtils::getCrossLayerInconsistency($context);

         // Score des patterns de requêtes (scraping, vélocité)
         $requestPattern = Utils\RequestUtils::getRequestPatternScore($context, $deviceData, $this->securityConfig['patterns'] ?? []);

         // Score des honeypots
         $honeypot = Utils\RequestUtils::getHoneypotScore($context, $this->securityConfig['honeypot'] ?? []);

         // Score des métriques comportementales client (souris, clavier)
         $behavior = Utils\RequestUtils::getBehaviorScore($context);

         // Score de détection de bot explicite (marqueurs d'automatisation)
         $bot = Utils\RequestUtils::getBotScore($context);

         // Score basé sur les listes de menaces (Threat Intelligence)
         $threatIntel = Utils\RequestUtils::getThreatIntelScore($context, $this->securityConfig['threatIntel'] ?? []);

         // Assemblage du vecteur de suspicion final
         $vector = [
             'inconsistencyScore' => $inconsistencyScore,
             'cookieDroppingScore' => (float)$identity['cookieDroppingScore'],
             'historyScore' => $behavioral['historyScore'],
             'rotationScore' => $behavioral['rotationScore'],
             'headerAnomalyScore' => $headerAnomalies['headerAnomalyScore'],
             'tlsSpoofingScore' => $tlsSpoofing['tlsSpoofingScore'],
             'timeInconsistencyScore' => $timeInconsistency['timeInconsistencyScore'],
             'crossLayerInconsistencyScore' => $crossLayerInconsistency['crossLayerInconsistencyScore'],
             'requestPatternScore' => $requestPattern['requestPatternScore'],
             'honeypotScore' => $honeypot['honeypotScore'],
             'behaviorScore' => $behavior['behaviorScore'],
             'botScore' => $bot['botScore'],
             'threatIntelScore' => $threatIntel['threatIntelScore'],
         ];
 
         // Sauvegarder l'état mis à jour de l'appareil dans le store
         $store->set("device:{$deviceId}", $deviceData);
 
         return $vector;
     }

     /**
      * Traite une requête entrante et retourne une décision.
      * @param RequestContext $context Le contexte de la requête.
      * @return array{action: string, score: float, vector: array, status?: int, body?: mixed, cookie?: array, path?: string, newCookieForResponse?: array}
      */
     public function processRequest(RequestContext $context): array
     {
         $this->log('Processing request', ['clientIp' => $context->clientIp, 'path' => $context->path]);
 
         // 1. Vérifier les listes blanches
         if ($this->checkAllowlists($context)) {
             return ['action' => 'next', 'score' => 0.0, 'vector' => ['whitelisted' => 100]];
         }
 
         $store = StoreManager::getStore();
         $thresholds = $this->securityConfig['thresholds'];
 
         // 2. Gérer la soumission d'une solution de challenge
         $powNonce = $context->query['pow_nonce'] ?? null;
         if ($powNonce) {
             $this->log('Challenge solution submitted', ['pow_type' => $context->query['pow_type'] ?? 'unknown', 'nonce' => $powNonce]);
             $challengeContext = $store->get("secret:{$powNonce}");
 
             if ($challengeContext) {
                 $isValid = false;
                 $ticket = null;
                 $ticketTtl = $this->securityConfig['ticketMaxAge'] ?? 3600000; // 1 heure par défaut
 
                 $powType = $context->query['pow_type'] ?? null;
                 if ($powType === 'cpu_target' || $powType === 'cpu_mem') {
                     $cpuSolution = $context->query['pow_solution_cpu'] ?? $context->query['pow_solution'] ?? null;
                     if ($cpuSolution) {
                         $ticket = ChallengeUtils::verifyCpuTargetPoWAndGenerateTicket(
                             $context->clientIp,
                             $ticketTtl,
                             $powNonce,
                             $cpuSolution,
                             $challengeContext
                         );
                         $isValid = $ticket !== null;
 
                         if ($powType === 'cpu_mem') {
                             $memSolution = $context->query['pow_solution_mem'] ?? null;
                             $isMemValid = $memSolution ? ChallengeUtils::verifyMemoryPoW(
                                 $powNonce,
                                 $memSolution,
                                 $challengeContext['memDifficulty'] ?? 0,
                                 $challengeContext['clientSecret'] ?? ''
                             ) : false;
                             $isValid = $isValid && $isMemValid;
                         }
                     }
                 }
 
                 if ($isValid) {
                     $store->delete("secret:{$powNonce}");
                     $this->log('Challenge solution valid - issuing ticket', ['ticketMaxAge' => $ticketTtl]);
 
                     $originalPath = $challengeContext['originalPath'] ?? '/';
                     return [
                         'action' => 'redirect',
                         'path' => $originalPath,
                         'score' => 0.0,
                         'vector' => ['challenge_solved' => 100],
                         'cookie' => [
                             'name' => 'pow_clearance',
                             'value' => $ticket,
                             'options' => ['httponly' => true, 'secure' => $this->isProduction, 'expires' => time() + ($ticketTtl / 1000), 'path' => '/']
                         ]
                     ];
                 } else {
                     $this->log('Challenge solution invalid', ['nonce' => $powNonce], 'warn');
                     // Si la solution est invalide, on pénalise fortement pour forcer un nouveau challenge plus difficile.
                     // On ne retourne pas tout de suite, on laisse la logique continuer avec un score élevé.
                     $suspicionVector['honeypotScore'] = 100;
                 }
             } else {
                 $this->log('Challenge context not found or expired', ['nonce' => $powNonce], 'warn');
                 $suspicionVector['honeypotScore'] = 100; // Tentative de probing
             }
         }
 
         // 3. Vérifier un ticket existant
         $powCookie = $context->cookies['pow_clearance'] ?? null;
         if (ChallengeUtils::isTicketValid($context->clientIp, $powCookie)) {
             $this->log('Valid clearance ticket found - allowing request');
             return ['action' => 'next', 'score' => 0.0, 'vector' => ['ticket_valid' => 100]];
         }
 
         // 4. Calculer le score de suspicion
         $suspicionVector = $this->getSuspicionVector($context);
         $finalScore = $this->calculateFinalScore($suspicionVector);
         $this->log('Final score calculated', ['finalScore' => $finalScore]);
 
         // Préparer la réponse finale
         $response = [
             'action' => 'next',
             'score' => $finalScore,
             'vector' => $suspicionVector
         ];
         // 5. Prendre une décision basée sur le score
         $blockThreshold = $thresholds['block'] ?? 95;
         if ($finalScore >= $blockThreshold) {
             $this->log('Request blocked - score exceeded block threshold', ['finalScore' => $finalScore, 'blockThreshold' => $blockThreshold], 'warn');
             return ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => $finalScore, 'vector' => $suspicionVector];
         }
 
         $lowThreshold = $thresholds['low'] ?? 20;
         if ($finalScore >= $lowThreshold) {
             $this->log('Suspicious request - issuing challenge', ['finalScore' => $finalScore]);
 
             $nonce = bin2hex(random_bytes(16));
             $clientSecret = bin2hex(random_bytes(16));
 
             $suspicionFactor = ($finalScore - $lowThreshold) / (($thresholds['high'] ?? 75) - $lowThreshold);
             $suspicionFactor = max(0, min(1.5, $suspicionFactor));
 
             $cpuChallengeDetails = [
                 'type' => 'cpu_target',
                 'nonce' => $nonce,
                 'target' => ChallengeUtils::calculateCpuTarget($suspicionFactor, $this->securityConfig),
                 'path' => $context->path,
             ];
 
             $memActivationFactor = max(0, ($suspicionFactor - 0.25) / 0.75);
             $memDifficulty = (int)round($memActivationFactor * 48); // 0 à 48MB
 
             $originalFingerprint = Utils\RequestUtils::getCompositeDeviceHash($context);
             $baseBlock = ChallengeUtils::createCpuChallengeBaseBlock($nonce, $clientSecret, $originalFingerprint);
 
             $challengeContext = [
                 'clientSecret' => $clientSecret,
                 'cpuTarget' => $cpuChallengeDetails['target'],
                 'suspicionScore' => $finalScore,
                 'fingerprint' => $originalFingerprint,
                 'memDifficulty' => $memDifficulty,
                 'baseBlock' => $baseBlock,
                 'originalPath' => $context->path,
             ];
 
             $store->set("secret:{$nonce}", $challengeContext, $this->securityConfig['challengeTtl'] ?? 300);
 
             $this->log('Challenge issued', ['nonce' => $nonce, 'ttl' => $this->securityConfig['challengeTtl'] ?? 300]);
 
             // Pour les API, retourner un challenge JSON
             if (str_contains($context->getHeader('accept') ?? '', 'application/json')) {
                 $challengePayload = [
                     'challenge' => [
                         'type' => 'cpu_mem',
                         'nonce' => $nonce,
                         'clientSecret' => $clientSecret,
                         'cpuTarget' => $cpuChallengeDetails['target'],
                         'memDifficulty' => $memDifficulty,
                         'baseBlock' => array_values(unpack('C*', $baseBlock)), // Envoyer comme un tableau d'octets
                     ]
                 ];
                 return ['action' => 'challenge', 'score' => $finalScore, 'vector' => $suspicionVector, 'status' => 403, 'body' => $challengePayload];
             }
 
             // Pour les navigateurs, retourner une page HTML
             // Note: La génération de la page HTML est omise ici pour la simplicité,
             // mais elle devrait être implémentée en se basant sur generateCombinedPoWChallengePage de JS.
             $challengeBody = "<h1>Challenge Required</h1><p>Please solve the challenge to continue.</p><!-- Challenge script would go here -->";
             return ['action' => 'challenge', 'score' => $finalScore, 'vector' => $suspicionVector, 'status' => 403, 'body' => $challengeBody];
         }
 
         // 6. Si le score est bas, autoriser la requête
         $this->log('Request passed - no challenge required', ['finalScore' => $finalScore]);
 
         // Si un nouveau cookie d'identification a été généré, on l'ajoute à la réponse.
         if (isset($context->newCookieForResponse)) {
             $response['newCookieForResponse'] = $context->newCookieForResponse;
         }
 
         return $response;
     }
 }
