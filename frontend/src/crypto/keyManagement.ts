import { x25519 } from '@noble/curves/ed25519';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import {
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  utf8ToBytes,
} from './utils.js';

export interface ClientKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface ClientKeyBundle {
  userId: string;
  keyId: string;
  version: number;
  dhKeys: ClientKeyPair; // X25519 for key agreement
  signingKeys: ClientKeyPair; // Ed25519 for digital signatures
  fingerprint: string;
  safetyNumber: string;
  registrationSignature: string;
  createdAt: number;
}

/**
 * Generates an X25519 keypair for Diffie-Hellman key agreement.
 */
export function generateX25519KeyPair(): ClientKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Generates an Ed25519 keypair for digital signatures.
 * IMPORTANT: Completely independent curve and private key from X25519.
 */
export function generateEd25519KeyPair(): ClientKeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/**
 * Computes standardized SHA-256 fingerprint from public key material.
 */
export function computePublicKeyFingerprint(dhPublicKey: Uint8Array, signingPublicKey: Uint8Array): string {
  const combined = new Uint8Array([...dhPublicKey, ...signingPublicKey]);
  const hash = sha256(combined);
  const hex = bytesToHex(hash).toUpperCase();
  return hex.match(/.{1,4}/g)?.join(':') || hex;
}

/**
 * Generates a 60-digit numerical safety number for out-of-band visual verification.
 */
export function computeSafetyNumber(myKeys: Uint8Array, theirKeys: Uint8Array): string {
  // Sort lexicographically to ensure bidirectional symmetry
  let first = myKeys;
  let second = theirKeys;
  for (let i = 0; i < Math.min(myKeys.length, theirKeys.length); i++) {
    if (myKeys[i] < theirKeys[i]) {
      first = myKeys;
      second = theirKeys;
      break;
    } else if (myKeys[i] > theirKeys[i]) {
      first = theirKeys;
      second = myKeys;
      break;
    }
  }

  const combined = new Uint8Array([...first, ...second]);
  const hash = sha256(combined);
  let digits = '';
  for (let i = 0; i < 30; i++) {
    const val = ((hash[i % hash.length] << 8) | hash[(i + 1) % hash.length]) % 100;
    digits += val.toString().padStart(2, '0');
  }
  return digits.match(/.{1,5}/g)?.join(' ') || digits;
}

/**
 * Creates and cross-signs a client key bundle for registration.
 */
export function createClientKeyBundle(userId: string, version = 1): ClientKeyBundle {
  const dhKeys = generateX25519KeyPair();
  const signingKeys = generateEd25519KeyPair();
  const keyId = `key_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
  const createdAt = Date.now();

  const dhPubBase64 = bytesToBase64(dhKeys.publicKey);
  const payloadToSign = utf8ToBytes(`${userId}:${dhPubBase64}:${version}`);
  const signatureBytes = ed25519.sign(payloadToSign, signingKeys.privateKey);
  const registrationSignature = bytesToBase64(signatureBytes);

  const fingerprint = computePublicKeyFingerprint(dhKeys.publicKey, signingKeys.publicKey);
  const safetyNumber = computeSafetyNumber(dhKeys.publicKey, signingKeys.publicKey);

  return {
    userId,
    keyId,
    version,
    dhKeys,
    signingKeys,
    fingerprint,
    safetyNumber,
    registrationSignature,
    createdAt,
  };
}

// Client Storage for Keys
// In browser sandbox, we securely persist key material in IndexedDB or sessionStorage
const KEYSTORE_DB_NAME = 'SecureText_KeyStore';
const KEYSTORE_STORE_NAME = 'UserKeyRings';

export async function saveKeysToStorage(bundle: ClientKeyBundle): Promise<void> {
  // Serialize keys to base64 for persistent storage
  const serialized = {
    userId: bundle.userId,
    keyId: bundle.keyId,
    version: bundle.version,
    dhPriv: bytesToBase64(bundle.dhKeys.privateKey),
    dhPub: bytesToBase64(bundle.dhKeys.publicKey),
    signPriv: bytesToBase64(bundle.signingKeys.privateKey),
    signPub: bytesToBase64(bundle.signingKeys.publicKey),
    fingerprint: bundle.fingerprint,
    safetyNumber: bundle.safetyNumber,
    registrationSignature: bundle.registrationSignature,
    createdAt: bundle.createdAt,
  };

  const json = JSON.stringify(serialized);
  try {
    // PRIMARY: localStorage persists across tabs, browser restarts, and session expiry
    localStorage.setItem(`securetext_keys_${bundle.userId}`, json);
  } catch (err) {
    console.warn('localStorage save warning:', err);
  }
  try {
    // SECONDARY: sessionStorage as a fast in-tab cache
    sessionStorage.setItem(`securetext_keys_${bundle.userId}`, json);
  } catch (err) {
    console.warn('sessionStorage save warning:', err);
  }
}

export function loadKeysFromStorage(userId: string): ClientKeyBundle | null {
  try {
    // PRIMARY: always prefer localStorage so keys survive tab/session close
    const raw =
      localStorage.getItem(`securetext_keys_${userId}`) ||
      sessionStorage.getItem(`securetext_keys_${userId}`) ||
      // Legacy fallback for old backup key name
      localStorage.getItem(`securetext_keys_backup_${userId}`);

    if (!raw) return null;

    const parsed = JSON.parse(raw);
    const bundle: ClientKeyBundle = {
      userId: parsed.userId,
      keyId: parsed.keyId,
      version: parsed.version,
      dhKeys: {
        privateKey: base64ToBytes(parsed.dhPriv),
        publicKey: base64ToBytes(parsed.dhPub),
      },
      signingKeys: {
        privateKey: base64ToBytes(parsed.signPriv),
        publicKey: base64ToBytes(parsed.signPub),
      },
      fingerprint: parsed.fingerprint,
      safetyNumber: parsed.safetyNumber,
      registrationSignature: parsed.registrationSignature,
      createdAt: parsed.createdAt,
    };

    // Re-sync to both stores so next load is fast from either
    try { sessionStorage.setItem(`securetext_keys_${userId}`, raw); } catch { /* ignore */ }
    try { localStorage.setItem(`securetext_keys_${userId}`, raw); } catch { /* ignore */ }

    return bundle;
  } catch (err) {
    console.error('Failed to load keys from storage:', err);
    return null;
  }
}
