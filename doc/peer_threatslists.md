# Peer Threat Lists & Federated Threat Intelligence

The **Fingerprint** security suite integrates a **threat sharing federation** mechanism (`federatedPeers`). This system allows different independent instances (or federated nodes) to propagate and synchronize the cryptographic identities of banned malicious terminals in real-time, without ever disclosing personal data (such as raw IP addresses or session cookies).

---

## Core Concepts

When a client is blocked by the detection engine (suspicion score greater than or equal to the blocking threshold, e.g., $\ge 95$), the system extracts the Zero-Knowledge Proof (ZKP) public key of this client from the `X-ZKP-Proof` header (the $y$ component of the `y:t:s` triplet).

Federated sharing relies on the following principles:
1. **Total Anonymity**: Only the public key $y$ (a mathematical hash derived from the Schnorr zero-knowledge proof) is propagated. IP addresses and browsing history never leave the origin server.
2. **Non-repudiation and Integrity**: All communications between peers are cryptographically signed using Ed25519 asymmetric key pairs (which are generated automatically on-load by default). This eliminates the need to manually sync or share symmetric secrets across nodes.
3. **Replay Resistance**: Each synchronization message includes a timestamp in milliseconds combined with a strict clock drift verification (max. 5 minutes).

---

## Federated Alert Lifecycle
```
[ Malicious Client ] ──> Blocked on [ Node A ]
                               │
                               ▼ (Extraction of the public ZKP y)
                         [ Node A ] ──(Signed Broadcast)──> [ Node B / Node C ]
                                                                 │
                                                                 ▼ (Verification and Local Ban)
                                                           [ Node B ] blocks the client
```

1. **Detection & Blocking**: A bot or an attacker attempts a malicious action on **Node A**. Its score exceeds the blocking threshold.
2. **Extraction & Validation**: **Node A** cryptographically validates the ZKP proof submitted by the client to ensure that the device's identity is authentic (anti-spoofing).
3. **Local Banning**: **Node A** stores the key $y$ in its local datastore (`banned-zkp-y:${zkpY}`) with a default time-to-live (TTL) of 30 days.
4. **Asynchronous Propagation**: In a non-blocking manner (via a thread or an asynchronous request), **Node A** sends a POST request to all peers configured in `federatedPeers` on their cooperative endpoint.
5. **Peer Verification**: The receiving nodes (**Node B**, etc.) receive the synchronization request (`coop_op=share_threat_intel`), validate the sender's IP address, the freshness of the timestamp, and the HMAC signature before adding the banned key to their own local database.

---

## Federation Configuration

Thanks to the **automatic on-load Ed25519 key generation**, setting up federated threat sharing is extremely simplified. You don't need to manually distribute or coordinate symmetric secrets.

### Node.js / Express
```javascript
import { createSecurityProfile } from '@anonympins/fingerprint';

const config = createSecurityProfile('balanced', {
    federatedPeers: [
        'https://node-b.legit-network.net/api/security',
        'https://node-c.legit-network.net/api/security'
    ],
    useAsymmetricTickets: true // Automatically generates/uses Ed25519 keys for signing
});
```

### PHP (Direct Integration)
```php
use Anonympins\Fingerprint\Config\SecurityProfiles;

$securityConfig = SecurityProfiles::createSecurityProfile('balanced', [
    'federatedPeers' => [
        'https://node-b.legit-network.net/api/security',
        'https://node-c.legit-network.net/api/security'
    ],
    'useAsymmetricTickets' => true // Uses default auto-generated keys
]);
```

---

## Community Trusted Peer Lists

You can connect to community-maintained trusted peers to instantly benefit from shared global threat intelligence. Below is a list of recommended community bootstrap nodes:

*   `primals.net` (Main coordination node)
*   `web.primals.net` (Web application reputation)
*   `ici.primals.net` (Regional integration endpoint)
*   `data.primals.net` (Shared threat intelligence database)
*   `games.primals.net` (High-interaction environment pool)

Example setup with community peers:

```javascript
federatedPeers: [
    'https://primals.net/',
    'https://web.primals.net/',
    'https://ici.primals.net/',
    'https://data.primals.net/',
    'https://games.primals.net/'
]
```

---

## Communication Protocol (Technical Specifications)

Threat information is exchanged via an HTTP POST request containing the following parameters:

### URL Parameters
* `coop_op=share_threat_intel`: Tells the receiving endpoint that this is a threat synchronization.

### Required HTTP Headers
* `X-Federation-Signature`: Ed25519 signature of the payload, verified using the sender's public key (automatically resolved or shared).
* `X-Federation-Timestamp`: Sender's system timestamp in milliseconds when the request was sent.

### Request Body (JSON)
```json
{
  "zkpY": "3b5379916d2b3882253c42885956a350..."
}
```

---

## Security & Poisoning Mitigation

To prevent a compromised node or an external attacker from injecting false alerts (poisoning) to block legitimate users, the engine applies several safeguards:

*   **Sender IP Validation**: The receiving node resolves the hostname of each URL in its own `federatedPeers` list. If the synchronization POST request comes from an IP address not resolved by that list, it is instantly rejected.
*   **Strict Cryptographic Signature**: The Ed25519 asymmetric signature prevents any tampering. Because the engine generates high-entropy key pairs automatically on startup if missing, each node has a unique, secure identity out-of-the-box.
*   **Clock Skew Control**: The absolute difference between the receiver's system timestamp and the emitted `X-Federation-Timestamp` must not exceed 5 minutes (300,000 ms). Beyond that, the request is rejected to prevent replay attacks.
*   **ZKP Cryptographic Validation**: Before being propagated or accepted, the Zero-Knowledge Proof of the banned terminal is mathematically validated by both the sender and the receiver to guarantee that the terminal actually generated this identity and that it is not a randomly forged identifier.

---

## Associated Prometheus Metrics

Federated Threat Intelligence synchronization and activity feed your node's Prometheus metrics:

| Metric | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `fingerprint_threat_intel_received_total` | Counter | `status="accepted"\|"rejected"` | Number of threat synchronizations received from federated peers. |
| `fingerprint_threat_intel_broadcast_total` | Counter | None | Number of threat alerts sent and broadcast to your federated peers. |

---

*To learn more about the underlying cryptographic operation, please consult the Key Concepts and Suspicion Vectors documentation as well as the guide on Zero-Knowledge Proofs.*