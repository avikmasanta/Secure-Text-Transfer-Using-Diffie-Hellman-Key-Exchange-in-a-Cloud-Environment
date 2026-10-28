/**
 * SecureText Shared Cryptographic and Protocol Specifications
 * Standardized for X25519, HKDF-SHA-256, AES-256-GCM, and Ed25519
 */

export const PROTOCOL_VERSION = 'SecureText-v1.0';
export const HKDF_INFO_PREFIX = 'SecureText-v1-AES-GCM-MessageKey';

export interface UserProfile {
  id: string;
  email: string;
  fullName: string;
  createdAt: string;
}

export interface UserPublicKeyBundle {
  userId: string;
  keyId: string;
  version: number;
  dhPublicKey: string; // Base64 encoded X25519 public key (32 bytes)
  signingPublicKey: string; // Base64 encoded Ed25519 public key (32 bytes)
  signature: string; // Ed25519 self-signature over (userId + dhPublicKey + version + createdAt)
  fingerprint: string; // SHA-256 formatted hex/colon fingerprint
  safetyNumber: string; // Formatted 60-digit numerical safety number for visual verification
  createdAt: string;
  isRevoked: boolean;
}

export interface CanonicalAAD {
  version: string;
  messageId: string;
  senderId: string;
  recipientId: string;
  senderKeyId: string;
  recipientKeyId: string;
  ephemeralPublicKey: string;
  timestamp: number;
}

export interface EncryptedMessageEnvelope {
  messageId: string;
  senderId: string;
  recipientId: string;
  protocolVersion: string;
  senderKeyId: string;
  recipientKeyId: string;
  ephemeralPublicKey: string; // Base64 encoded X25519 ephemeral public key
  nonce: string; // Base64 encoded 12-byte (96-bit) IV
  ciphertext: string; // Base64 encoded AES-256-GCM ciphertext
  authTag: string; // Base64 encoded 16-byte (128-bit) GCM authentication tag
  signature: string; // Base64 encoded Ed25519 signature over canonical transcript
  canonicalAAD: string; // JSON string representation of CanonicalAAD used as additional authenticated data
  timestamp: number;
  deliveryStatus: 'sent' | 'stored_in_cloud' | 'delivered' | 'read';
}

export interface DecryptedMessage {
  messageId: string;
  senderId: string;
  recipientId: string;
  plaintext: string;
  timestamp: number;
  verificationDetails: MessageVerificationDetails;
}

export interface MessageVerificationDetails {
  protocolVersion: string;
  keyAgreementAlgorithm: 'X25519';
  keyDerivationAlgorithm: 'HKDF-SHA-256';
  symmetricAlgorithm: 'AES-256-GCM';
  signatureAlgorithm: 'Ed25519';
  signatureVerified: boolean;
  tagVerified: boolean;
  aadVerified: boolean;
  replayDetected: boolean;
  sharedSecretFingerprint: string; // Truncated SHA-256 of derived shared secret
  senderSigningFingerprint: string;
  recipientDHFingerprint: string;
}

export interface SecurityEventLog {
  id: string;
  userId?: string;
  eventType: 'KEY_GENERATED' | 'KEY_REGISTERED' | 'KEY_ROTATED' | 'MESSAGE_SENT' | 'MESSAGE_DECRYPTED' | 'TAMPER_DETECTED' | 'SIGNATURE_INVALID' | 'REPLAY_PREVENTED' | 'LOGIN_ATTEMPT' | 'UNAUTHORIZED_ACCESS';
  status: 'SUCCESS' | 'WARNING' | 'CRITICAL';
  details: string;
  metadata?: Record<string, unknown>;
  timestamp: string;
}

export interface ConversationSummary {
  participantId: string;
  participantName: string;
  participantEmail: string;
  participantFingerprint: string;
  lastMessageSnippet?: string;
  lastMessageTimestamp?: number;
  unreadCount: number;
}

export interface BenchmarkTrial {
  payloadSizeBytes: number;
  payloadLabel: string;
  keygenLatencyMs: number;
  dhAgreementLatencyMs: number;
  hkdfLatencyMs: number;
  aesGcmEncryptLatencyMs: number;
  aesGcmDecryptLatencyMs: number;
  signatureGenLatencyMs: number;
  signatureVerifyLatencyMs: number;
  cloudStorageUploadLatencyMs: number;
  cloudStorageDownloadLatencyMs: number;
  totalEndToEndLatencyMs: number;
  plaintextBytes: number;
  ciphertextBytes: number;
  envelopeBytes: number;
  ciphertextExpansionRatio: number;
}

export interface BenchmarkSummaryReport {
  timestamp: string;
  environment: {
    browserOrRuntime: string;
    os: string;
    hardwareSpec: string;
  };
  trials: BenchmarkTrial[];
  comparativeBaseline: {
    tlsOnlyLatencyMs: number;
    presharedAesGcmLatencyMs: number;
    proposedDHSystemLatencyMs: number;
    playfairDemonstrationLatencyMs: number;
  };
}
