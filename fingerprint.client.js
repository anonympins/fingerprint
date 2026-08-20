import { cyrb53, FingerprintBuilder } from './fingerprint.builder.js';

// Cache pour éviter de recalculer les constantes (Hardware, etc.)
let cachedBuilder = null;

/**
 * Génère l'empreinte de l'appareil actuel.
 */
export const getDeviceFingerprint = () => {
  if (typeof window === "undefined") {
    console.error("getDeviceFingerprint can only be called on the client-side.");
    return "";
  }

  if (!cachedBuilder) {
    const nav = window.navigator;
    const screen = window.screen;

    cachedBuilder = new FingerprintBuilder();

    // 1. Hardware (Très stable) : Cœurs, RAM, GPU (si dispo via canvas), Touch
    cachedBuilder.add(
      "hw",
      `${nav.hardwareConcurrency}_${nav.deviceMemory}_${nav.maxTouchPoints}`,
    );

    // 2. Geo/Locale (Stable sauf voyage/VPN) : Timezone, Langue
    cachedBuilder.add(
      "geo",
      `${Intl.DateTimeFormat().resolvedOptions().timeZone}_${nav.language}_${new Date().getTimezoneOffset()}`,
    );

    // 3. Screen (Stable sauf changement moniteur/zoom) : Dimensions, ColorDepth
    cachedBuilder.add(
      "scr",
      `${screen.width}x${screen.height}_${screen.colorDepth}`,
    );

    // 4. Platform (Stable) : OS, Engine
    cachedBuilder.add("os", nav.platform);

    // 5. Graphics (WebGL Vendor/Renderer) - Invariant matériel fort
    try {
      const canvas = document.createElement("canvas");
      const gl =
        canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
        if (debugInfo) {
          const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
          const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          cachedBuilder.add("gpu", `${vendor}_${renderer}`);
        }
      }
    } catch (e) {}

    // 6. Canvas Fingerprinting (Rendering quirks)
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      if (ctx) {
        canvas.width = 200;
        canvas.height = 50;
        ctx.textBaseline = "alphabetic";
        ctx.font = "14px 'Arial'";
        ctx.fillStyle = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069";
        ctx.fillText("Primals", 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
        ctx.fillText("Primals", 4, 17);
        cachedBuilder.add("cvs", canvas.toDataURL());
      }
    } catch (e) {}

    // 7. Bot Detection (Indication cachée)
    if (nav.webdriver) cachedBuilder.add("bot", "true");
  }

  return cachedBuilder.toString();
};

/**
 * Génère une signature de requête incluant le contexte.
 * @param {object} payload
 */
export const generateRequestSignature = (payload = {}) => {
  const deviceFp = getDeviceFingerprint();
  const sortedPayload = Object.keys(payload)
    .sort()
    .map((k) => `${k}=${payload[k]}`)
    .join("&");
  const payloadHash = cyrb53(sortedPayload);
  return `${deviceFp}|req:${payloadHash}`;
};

/**
 * Génère une signature HMAC-SHA256 en utilisant l'API Web Crypto.
 * @param {object} payload - Les données à signer.
 * @param {string} secret - La clé secrète partagée.
 * @returns {Promise<string>} La signature hexadécimale.
 */
export const generateClientSideSignature = async (payload, secret) => {
  const sortedPayload = Object.keys(payload).sort().map((k) => `${k}=${payload[k]}`).join("&");
  const encoder = new TextEncoder();
  const key = await window.crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signatureBuffer = await window.crypto.subtle.sign("HMAC", key, encoder.encode(sortedPayload));
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
};