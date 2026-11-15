import { apiClient } from "./api";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";

export const analysisService = {
  // ─── Health ───────────────────────────────────────────────────────────────
  checkHealth: () => apiClient("/health"),

  // ─── Session ──────────────────────────────────────────────────────────────
  getHistory: () => apiClient("/session/history"),
  clearHistory: () => apiClient("/session/history", { method: "DELETE" }),
  getReport: (resultIndex) => apiClient(`/reports/${resultIndex}`),

  // ─── OSINT ────────────────────────────────────────────────────────────────
  analyzeOsint: (target) =>
    apiClient("/osint/analyze", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  // ─── Web & Network ────────────────────────────────────────────────────────
  scanDns: (target) =>
    apiClient("/web-network/dns", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  inspectHeaders: (target) =>
    apiClient("/web-network/headers", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  scanTls: (target) =>
    apiClient("/web-network/tls", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  scanTcp: (target, ports = [22, 80, 443, 8080]) =>
    apiClient("/web-network/tcp", {
      method: "POST",
      body: JSON.stringify({ target, ports }),
    }),

  getScanners: () => apiClient("/web-network/scanners"),

  scanNmap: (target, ports = [22, 80, 443, 8080]) =>
    apiClient("/web-network/nmap", {
      method: "POST",
      body: JSON.stringify({ target, ports }),
    }),

  scanRustscan: (target, ports = [22, 80, 443, 8080]) =>
    apiClient("/web-network/rustscan", {
      method: "POST",
      body: JSON.stringify({ target, ports }),
    }),

  // ─── Cryptography ─────────────────────────────────────────────────────────
  generateHashes: (target) =>
    apiClient("/cryptography/hashes", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  base64Encode: (target) =>
    apiClient("/cryptography/base64/encode", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  base64Decode: (target) =>
    apiClient("/cryptography/base64/decode", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  identifyHash: (target) =>
    apiClient("/cryptography/hash-identify", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  identifyCipher: (target) =>
    apiClient("/cryptography/cipher-identify", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  rotDecode: (target, shift) =>
    apiClient("/cryptography/rot/decode", {
      method: "POST",
      body: JSON.stringify({ target, shift }),
    }),

  morseEncode: (target) =>
    apiClient("/cryptography/morse/encode", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  morseDecode: (target) =>
    apiClient("/cryptography/morse/decode", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  brainfuckEncode: (target) =>
    apiClient("/cryptography/brainfuck/encode", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  brainfuckDecode: (target) =>
    apiClient("/cryptography/brainfuck/decode", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),

  aesGcmEncrypt: (plaintext, key) =>
    apiClient("/cryptography/aes-gcm/encrypt", {
      method: "POST",
      body: JSON.stringify({ plaintext, key }),
    }),

  aesGcmDecrypt: (ciphertext, key, nonce) =>
    apiClient("/cryptography/aes-gcm/decrypt", {
      method: "POST",
      body: JSON.stringify({ ciphertext, key, nonce }),
    }),

  rsaGenerateKeyPair: () =>
    apiClient("/cryptography/rsa/key-pair", { method: "POST", body: JSON.stringify({}) }),

  rsaSign: (value, private_key) =>
    apiClient("/cryptography/rsa/sign", {
      method: "POST",
      body: JSON.stringify({ value, private_key }),
    }),

  rsaVerify: (value, public_key, signature) =>
    apiClient("/cryptography/rsa/verify", {
      method: "POST",
      body: JSON.stringify({ value, public_key, signature }),
    }),

  generateToken: (bytes) =>
    apiClient("/cryptography/token", {
      method: "POST",
      body: JSON.stringify({ target: String(bytes) }),
    }),

  // ─── File Upload (multipart/form-data) ────────────────────────────────────
  /**
   * Upload a file to any file-based endpoint.
   * @param {string} endpoint  e.g. "/forensics/analyze"
   * @param {File}   file
   */
  analyzeFile: async (endpoint, file) => {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: "POST",
      credentials: "include",
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `Upload failed with status ${response.status}`);
    }

    return response.json();
  },
};
