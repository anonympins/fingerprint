=== Fingerprint Anti-Bot & Proof-of-Work ===
Contributors: anonympins
Tags: bot protection, security, proof of work, firewall, anti scraping
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.7.2
License: MIT
License URI: https://opensource.org/licenses/MIT

High-performance client-side anti-bot protection and Proof-of-Work challenge verification for WordPress without third-party CAPTCHA.

== Description ==

Fingerprint Anti-Bot is a high-performance, privacy-friendly bot mitigation engine for WordPress. It combines behavioral telemetry, TLS/HTTP2/QUIC transport inspection (JA3, JA4), passive TCP/IP stack analysis, and asynchronous Proof-of-Work (PoW) verification.

= Features =
* Transparent protection against scrapers, credential stuffers, and inventory scalpers.
* Multi-layered behavioral analysis (mouse, keystrokes, touch dynamics).
* Cryptographic Proof-of-Work challenges (CPU and Memory bound) without third-party CAPTCHA cookies or trackers.
* Prometheus-compatible metrics endpoint for monitoring and observability.
* Tailored security profiles for Frontend, Admin Area (wp-login), and REST API endpoints.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/fingerprint-anti-bot` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to **Settings -> Fingerprint Anti-Bot** to review security profiles, threshold adjustments, and Prometheus metrics.

== Frequently Asked Questions ==

= Does this plugin require an external cloud service? =
No. All evaluations, challenges, and validations occur directly on your WordPress server and client browser.

= Is HTTPS required? =
HTTPS is strongly recommended. Under unencrypted HTTP, modern browsers disable the Web Cryptography API (`crypto.subtle`), which reduces challenge verification performance.

== Changelog ==

= 0.7.2 =
* Added support for JA4 and QUIC protocol anomaly inspection.
* Improved subnet reputation tracking and Bayesian density scoring.
* Fixed WordPress Plugin Check compliance and removed restricted trademark terms.

= 0.7.0 =
* Initial release of Fingerprint Anti-Bot for WordPress.