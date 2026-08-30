<?php

 declare(strict_types=1);

 namespace Anonympins\Fingerprint;

 use Anonympins\Fingerprint\Config\SecurityProfiles;
 use Anonympins\Fingerprint\Store\StoreManager;
 use Anonympins\Fingerprint\Challenge\ChallengeUtils;
 use Anonympins\Fingerprint\Utils\BlockList;
 use Anonympins\Fingerprint\Utils\RequestUtils; 

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
             'honeypot', 'threatIntel', 'whitelist', 'isStaticResource', 'isApiRequest', 'logger', 'probationaryTtl',
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
             error_log($logMessage); // Écrit sur stderr, visible dans la console PHPUnit
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

     private function isHostPathInAllowlist(?string $requestHost, string $requestPath): bool
     {
         if (empty($requestHost)) {
             return false;
         }
 
         $whitelistRules = $this->securityConfig['whitelist'] ?? [];
         $hostPathRule = null;
         foreach ($whitelistRules as $rule) {
             if (($rule['type'] ?? '') === 'host_path_allowlist') {
                 $hostPathRule = $rule;
                 break;
             }
         }
 
         if (empty($hostPathRule['entries'])) {
             return false;
         }
 
         foreach ($hostPathRule['entries'] as $entry) {
             if (RequestUtils::hostPathMatches($requestHost, $requestPath, $entry)) {
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
         if ($this->isHostPathInAllowlist($context->getHeader('host'), $context->path)) {
             $this->log('Host and path in allowlist - allowing request', ['host' => $context->getHeader('host'), 'path' => $context->path]);
             return true;
         }
         if ($this->verifyWhitelistedBot($context)) {
             $this->log('Whitelisted bot verified - allowing request', ['clientIp' => $context->clientIp]);
             return true;
         }
 
         return false;
     }

     /**
      * @return array{deviceId: string, deviceData: ?array, newCookie: ?array}
       */
     private function resolveRequestIdentity(RequestContext $context, array &$suspicionVector): array
     {
         $this->log('Resolving request identity', ['clientIp' => $context->clientIp, 'cookies' => $context->cookies]);
         $store = StoreManager::getStore();
         $existingDeviceId = $context->cookies['device_id'] ?? null; // @phpstan-ignore-line
         $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
         $pendingCookieTtl = 120; // 2 minutes pour détecter la suppression

         $deviceId = $existingDeviceId;
         $deviceData = null;
         $newCookie = null;

         if ($deviceId) {
             $deviceData = $store->get("device:{$deviceId}");
         }

         if ($deviceData === null) {
             // Nouvel utilisateur ou cookie perdu/invalide
             $pendingDeviceId = $store->get("pending_cookie:{$context->clientIp}");
             if ($pendingDeviceId && !$existingDeviceId) {
                 // La pénalité est maintenant ajoutée directement au vecteur de suspicion.
                 $this->log('Cookie dropping detected', ['clientIp' => $context->clientIp, 'pendingDeviceId' => $pendingDeviceId]);
                 $suspicionVector['cookieDroppingScore'] = 100.0;
             }

             $deviceId = bin2hex(random_bytes(16)); // UUID-like

             // Préparer le cookie à envoyer
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
                 'ips' => [$context->clientIp],
                 'requestHistory' => [],
                 'lastUpdate' => time() * 1000,
                 'lastFpHash' => $currentDeviceHash,
                 'lastChangeTimestamp' => 0,
                 'rapidChangeCount' => 0,
                 'highScoreCount' => 0,
                 'lastHighScoreTimestamp' => 0,
             ];
         } else {
             // S'assurer que 'ips' est un tableau pour les opérations suivantes.
             if (!isset($deviceData['ips']) || !is_array($deviceData['ips'])) { // @phpstan-ignore-line
                 $deviceData['ips'] = [];
             }
         }

         return [
             'deviceId' => $deviceId,
             'deviceData' => $deviceData,
             'newCookie' => $newCookie,
         ];
     }

     /**
      * @return array<string, float>
      */
     public function getSuspicionVector(RequestContext $context, array &$suspicionVector): array
     {
         $store = StoreManager::getStore();
         $identity = $this->resolveRequestIdentity($context, $suspicionVector);
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

         // Score d'incohérence du fingerprint. Pour un nouvel appareil, le score est de 0.
         $inconsistencyScore = 0.0;
         if (isset($deviceData['initialDeviceHash'])) {
             $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
             $consistencyScore = FingerprintBuilder::compare($deviceData['initialDeviceHash'], $currentDeviceHash);
             $inconsistencyScore = min(100.0, max(0.0, (1 - $consistencyScore) * 200));
             if ($consistencyScore < ($this->securityConfig['similarityThreshold'] ?? 0.7)) {
                 $inconsistencyScore = 100.0;
             }
             $this->log('Inconsistency score calculated', ['initial' => $deviceData['initialDeviceHash'], 'current' => $currentDeviceHash, 'consistency' => $consistencyScore, 'score' => $inconsistencyScore]);
         }

         $behavioral = RequestUtils::getBehavioralIndicators($context, $deviceData);

         // Score des anomalies d'en-têtes
         $headerAnomalies = RequestUtils::getHeaderAnomalies($context);

         // Score de spoofing TLS
         $tlsSpoofing = RequestUtils::getTlsSpoofingScore($context);

         // Score d'incohérence temporelle (attaque par rejeu)
         $timeInconsistency = RequestUtils::getTimeInconsistencyScore($context);

         // Score des incohérences entre couches (client vs serveur)
         $crossLayerInconsistency = RequestUtils::getCrossLayerInconsistency($context);

         // Score des patterns de requêtes (scraping, vélocité)
         $requestPattern = RequestUtils::getRequestPatternScore($context, $deviceData, $this->securityConfig['patterns'] ?? []);

         // Score des honeypots
         $honeypot = RequestUtils::getHoneypotScore($context, $this->securityConfig['honeypot'] ?? []);

         // Score des métriques comportementales client (souris, clavier)
         $behavior = RequestUtils::getBehaviorScore($context);

         // Score de détection de bot explicite (marqueurs d'automatisation)
         $bot = RequestUtils::getBotScore($context);

         // Score basé sur les listes de menaces (Threat Intelligence)
         $threatIntel = RequestUtils::getThreatIntelScore($context, $this->securityConfig['threatIntel'] ?? []);

         // Assemblage du vecteur de suspicion final
         $suspicionVector = array_merge($suspicionVector, [
             'inconsistencyScore' => $inconsistencyScore,
             'historyScore' => $behavioral['historyScore'],
             'rotationScore' => $behavioral['rotationScore'],
             'headerAnomalyScore' => $headerAnomalies['headerAnomalyScore'],
             'tlsSpoofingScore' => $tlsSpoofing['tlsSpoofingScore'],
             'timeInconsistencyScore' => $timeInconsistency['timeInconsistencyScore'],
             'crossLayerInconsistencyScore' => $crossLayerInconsistency['crossLayerInconsistencyScore'],
             'requestPatternScore' => $requestPattern['requestPatternScore'], // Ce score est maintenant calculé
             'honeypotScore' => $honeypot['honeypotScore'],
             'behaviorScore' => $behavior['behaviorScore'],
             'botScore' => $bot['botScore'],
             'threatIntelScore' => $threatIntel['threatIntelScore'],
         ]);
 
         // Sauvegarder l'état mis à jour de l'appareil dans le store
         $store->set("device:{$deviceId}", $deviceData);
 
         return $suspicionVector;
     }

     /**
      * Traite une requête entrante et retourne une décision.
      * @param RequestContext $context Le contexte de la requête.
      * @return array{action: string, score: float, vector: array, status?: int, body?: mixed, cookie?: array, path?: string, newCookieForResponse?: array}
      */
     public function processRequest(RequestContext $context): array
     {
         $this->log('Processing request', ['clientIp' => $context->clientIp, 'path' => $context->path]);
 
         // Parse GraphQL query if applicable
         if ($context->path === '/graphql' && !empty($context->body)) {
             $gqlInfo = RequestUtils::parseGraphQLQuery(is_array($context->body) ? $context->body : []);
             if ($gqlInfo) {
                 $context->graphqlOperation = $gqlInfo;
             }
         }
 
         // 1. Vérifier les listes blanches
         if ($this->checkAllowlists($context)) {
             return ['action' => 'next', 'score' => 0.0, 'vector' => ['whitelisted' => 100.0]];
         }
 
         // Initialiser le vecteur de suspicion
         $suspicionVector = [];
 
         // Résoudre l'identité et vérifier le statut "condamné"
         $identity = $this->resolveRequestIdentity($context, $suspicionVector);
         $deviceId = $identity['deviceId'];
         $deviceData = $identity['deviceData'];
         if ($deviceData && ($deviceData['condemned'] ?? false)) {
             $this->log('Device condemned - blocking request', ['deviceId' => $deviceId], 'warn');
             return ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => 100, 'vector' => ['honeypotScore' => 100]];
         }
 
         $store = StoreManager::getStore();
         $thresholds = $this->securityConfig['thresholds'];
 
         // 2. Gérer la soumission d'une solution de challenge
         $powNonce = $context->query['pow_nonce'] ?? null;
         if ($powNonce) {
             $this->log('Challenge solution submitted', ['pow_type' => $context->query['pow_type'] ?? 'unknown', 'nonce' => $powNonce]); // @phpstan-ignore-line
             $challengeContext = $store->get("secret:{$powNonce}");
 
             if ($challengeContext) {
                 $isValid = false;
                 $ticket = null;
 
                 $powType = $context->query['pow_type'] ?? null;
                 if ($powType === 'cpu_target' || $powType === 'cpu_mem') {
                     $cpuSolution = $context->query['pow_solution_cpu'] ?? $context->query['pow_solution'] ?? null;
                    if ($cpuSolution) {
                        $ticket = ChallengeUtils::verifyCpuTargetPoWAndGenerateTicket(
                            $context->clientIp,
                            3600000, // TTL temporaire, sera ajusté
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
 
                 // Vérification de la cohérence du fingerprint
                 $solverFingerprint = $context->query['pow_fp'] ?? RequestUtils::getCompositeDeviceHash($context);
                 $originalFingerprint = $challengeContext['fingerprint'] ?? '';
                 $similarity = FingerprintBuilder::compare($originalFingerprint, $solverFingerprint);
                 $similarityThreshold = $this->securityConfig['similarityThreshold'] ?? 0.95;
 
                 if ($similarity < $similarityThreshold) {
                     $this->log('Fingerprint mismatch - challenge solved on a different machine!', [
                         'similarity' => round($similarity, 4),
                         'threshold' => $similarityThreshold
                     ], 'warn');
                     $isValid = false;
                 }
 
                 if ($isValid) {
                     $store->delete("secret:{$powNonce}"); // @phpstan-ignore-line
 
                     // Logique de ticket probatoire
                     $preliminaryScore = $challengeContext['suspicionScore'] ?? 0;
                     $isProbationary = $preliminaryScore >= $thresholds['low'];
                     $probationaryTtl = $this->securityConfig['probationaryTtl'] ?? 30000; // 30s
                     $optimalTtl = $this->securityConfig['ticketMaxAge'] ?? 3600000;
                     $finalTtl = $isProbationary ? $probationaryTtl : $optimalTtl;
 
                     $this->log('Challenge solution valid - issuing ticket', ['ticketMaxAge' => $finalTtl, 'isProbationary' => $isProbationary]);
 
                     $originalPath = $challengeContext['originalPath'] ?? '/';
                     return [
                         'action' => 'redirect',
                         'path' => RequestUtils::cleanUrlFromPowParams($originalPath, $context->query), // @phpstan-ignore-line
                         'score' => 0.0,
                         'vector' => ['challenge_solved' => 100],
                         'cookie' => [
                             'name' => 'pow_clearance',
                             'value' => ChallengeUtils::regenerateTicketWithTtl($ticket, $context->clientIp, $finalTtl),
                             'options' => ['httponly' => true, 'secure' => $this->isProduction, 'expires' => time() + ($finalTtl / 1000), 'path' => '/']
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
         $hasValidTicket = false;
         $powCookie = $context->cookies['pow_clearance'] ?? null;
         if (ChallengeUtils::isTicketValid($context->clientIp, $powCookie)) {
             $hasValidTicket = true;
             // On ne retourne pas tout de suite pour permettre le re-challenge
             // $this->log('Valid clearance ticket found');
             // return ['action' => 'next', 'score' => 0.0, 'vector' => ['ticket_valid' => 100]];
         }
 
         // 4. Calculer le vecteur et le score de suspicion
         $suspicionVector = $this->getSuspicionVector($context, $suspicionVector);
         $finalScore = $this->calculateFinalScore($suspicionVector);
         $this->log('Suspicion vector and final score calculated', [
             'finalScore' => round($finalScore, 2),
             'vector' => $suspicionVector
         ]);
 
         // Logique pour challenger les nouveaux appareils (déplacée ici pour avoir le score final)
         $isNewDevice = $identity['newCookie'] !== null;
         if ($isNewDevice && ($this->securityConfig['challengeNewDevices'] ?? false) && $finalScore < $thresholds['low']) {
             $this->log('New device - enforcing minimum challenge score', [
                 'originalScore' => $finalScore,
                 'enforcedScore' => $thresholds['low']
             ]);
             $finalScore = (float)$thresholds['low'];
         }
 
         // Vérifier les URL pièges (après calcul du score)
         $lastNonce = $deviceData['lastChallengeNonce'] ?? null;
         if ($lastNonce && ChallengeUtils::verifyTrapUrl($context->path, $context->query['sig'] ?? '', $lastNonce)) {
             $this->log('Honeypot trap URL triggered - condemning device', ['path' => $context->path, 'deviceId' => $deviceId]);
             $deviceData['condemned'] = true; // @phpstan-ignore-line
             $store->set("device:{$deviceId}", $deviceData); // Persiste le statut condamné
             return ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => 100, 'vector' => ['honeypotScore' => 100]];
         }
 
         // 5. Prendre une décision basée sur le score
         $blockThreshold = $thresholds['block'] ?? 95;
         if ($finalScore >= $blockThreshold) {
             $response = ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => $finalScore, 'vector' => $suspicionVector];
         } else {
             // Logique de re-challenge
             $highThreshold = $thresholds['high'] ?? 75;
             $mustReChallenge = $finalScore >= $highThreshold && $hasValidTicket;
 
             $lowThreshold = $thresholds['low'] ?? 20;
             if (($finalScore >= $lowThreshold && !$hasValidTicket) || $mustReChallenge) {
                 if ($mustReChallenge) {
                     $this->log('High suspicion score detected - overriding valid ticket to re-issue challenge', ['finalScore' => $finalScore, 'deviceId' => $deviceId]);
                 }
 
                 $this->log('Suspicious request - issuing challenge', ['finalScore' => $finalScore]);
 
                 $nonce = bin2hex(random_bytes(16));
                 $trapUrls = [ChallengeUtils::generateTrapUrl($nonce), ChallengeUtils::generateTrapUrl($nonce)];
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
 
                 $originalFingerprint = RequestUtils::getCompositeDeviceHash($context);
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
 
                 // Associer le nonce au device pour la vérification des URL pièges
                 if ($deviceData) {
                     $deviceData['lastChallengeNonce'] = $nonce;
                     $store->set("device:{$deviceId}", $deviceData); // @phpstan-ignore-line
                 }
 
                 $this->log('Challenge issued', ['nonce' => $nonce, 'ttl' => $this->securityConfig['challengeTtl'] ?? 300]);
 
                 $isApiRequest = false;
                 if (isset($this->securityConfig['isApiRequest']) && is_callable($this->securityConfig['isApiRequest'])) {
                     $isApiRequest = ($this->securityConfig['isApiRequest'])($context);
                 }
 
                 // Pour les API, retourner un challenge JSON
                 if ($isApiRequest) {
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
                     $response = ['action' => 'challenge', 'score' => $finalScore, 'vector' => $suspicionVector, 'status' => 403, 'body' => $challengePayload];
                 } else {
                     // Pour les navigateurs, retourner une page HTML
                     $pageBody = ChallengeUtils::generateCombinedPoWChallengePage(
                         $cpuChallengeDetails, $memDifficulty, $clientSecret, 
                         $this->securityConfig, $trapUrls, $originalFingerprint
                     );
                     $response = ['action' => 'challenge', 'score' => $finalScore, 'vector' => $suspicionVector, 'status' => 403, 'body' => $pageBody];
                 }
             } elseif ($hasValidTicket) {
                 // Si on arrive ici avec un ticket valide et un score bas, on autorise
                 $this->log('Valid clearance ticket found and score is low - allowing request');
                 $response = ['action' => 'next', 'score' => 0.0, 'vector' => ['ticket_valid' => 100]];
             } else {
                 // 6. Si le score est bas et qu'il n'y a pas de ticket, autoriser la requête
                 $this->log('Request passed - no challenge required', ['finalScore' => $finalScore]);
                 $response = ['action' => 'next', 'score' => $finalScore, 'vector' => $suspicionVector];
             }
         }
 
         // Si un nouveau cookie d'identification a été généré, on l'ajoute à la réponse.
         if (isset($context->newCookieForResponse)) {
             $response['newCookieForResponse'] = $context->newCookieForResponse;
         }
 
         return $response;
     }

     /**
      * Vérifie si l'opération GraphQL correspond à une entrée dans la liste blanche.
      */
     private function isGraphqlOperationInAllowlist(?string $operationType, ?string $operationName): bool
     {
         if (empty($operationType) || empty($operationName)) {
             return false;
         }

         $whitelistRules = $this->securityConfig['whitelist'] ?? [];
         $graphqlRule = null;
         foreach ($whitelistRules as $rule) {
             if (($rule['type'] ?? '') === 'graphql_operation_allowlist') {
                 $graphqlRule = $rule;
                 break;
             }
         }

         if (empty($graphqlRule['entries'])) {
             return false;
         }

         foreach ($graphqlRule['entries'] as $entry) {
             [$entryType, $entryName] = explode(':', $entry, 2);
             if ($entryType !== $operationType) {
                 continue;
             }

             if ($entryName === $operationName || $entryName === '*') {
                 return true;
             }
             if (str_ends_with($entryName, '*') && str_starts_with($operationName, substr($entryName, 0, -1))) {
                 return true;
             }
         }
         return false;
     }

     /**
      * Vérifie si une requête provient d'un bot légitime et whitelisté (ex: Googlebot)
      * en utilisant des recherches DNS inversées et directes. Le résultat est mis en cache.
      */
     private function verifyWhitelistedBot(RequestContext $context): bool
     {
         $whitelistRules = $this->securityConfig['whitelist'] ?? [];
         $botRules = array_filter($whitelistRules, fn($rule) => isset($rule['hostnameSuffix']));
         if (empty($botRules)) {
             return false;
         }

         $userAgent = $context->getHeader('user-agent') ?? '';
         $matchedRule = null;
         foreach ($botRules as $rule) {
             if (isset($rule['userAgent']) && preg_match('/' . $rule['userAgent'] . '/', $userAgent)) {
                 $matchedRule = $rule;
                 break;
             }
         }
         if ($matchedRule === null) {
             return false;
         }

         $store = StoreManager::getStore();
         $cacheKey = "ip-whitelist:{$context->clientIp}";
         $cachedStatus = $store->get($cacheKey);

         if ($cachedStatus === 'verified') return true;
         if ($cachedStatus === 'failed') return false;

         try {
             // 1. Reverse DNS lookup. gethostbyaddr peut être lent, mais c'est la méthode standard.
             // @ pour supprimer les warnings si l'IP n'a pas de PTR record.
             $hostname = @gethostbyaddr($context->clientIp);
             if ($hostname === false || $hostname === $context->clientIp) {
                 $store->set($cacheKey, 'failed', 86400);
                 return false;
             }

             $validHostname = null;
             if (str_ends_with($hostname, $matchedRule['hostnameSuffix'])) {
                 $validHostname = $hostname;
             }

             if ($validHostname === null) {
                 $store->set($cacheKey, 'failed', 86400);
                 return false;
             }
 
             // 2. Forward DNS lookup
             $addresses = array_merge(dns_get_record($validHostname, DNS_A) ?: [], dns_get_record($validHostname, DNS_AAAA) ?: []);
             $ips = array_column($addresses, 'ip');
 
             if (in_array($context->clientIp, $addresses)) {
                 $store->set($cacheKey, 'verified', 86400);
                 return true;
             }
         } catch (\Exception $e) { /* DNS errors */ }

         $store->set($cacheKey, 'failed', 86400);
         return false;
     }

 }
