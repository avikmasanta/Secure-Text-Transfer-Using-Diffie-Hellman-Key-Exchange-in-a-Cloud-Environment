import {
  UserProfile,
  UserPublicKeyBundle,
  EncryptedMessageEnvelope,
  SecurityEventLog,
} from '@securetext/shared';

export type { SecurityEventLog };

const API_BASE = '/api';

export function getStoredToken(): string | null {
  return localStorage.getItem('securetext_token');
}

export function setStoredToken(token: string) {
  localStorage.setItem('securetext_token', token);
}

export function clearStoredToken() {
  localStorage.removeItem('securetext_token');
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || `API request failed with status ${response.status}`);
  }

  return data as T;
}

// Authentication
export async function apiRegister(email: string, fullName: string, password: string) {
  return request<{ user: UserProfile; token: string }>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, fullName, password }),
  });
}

export async function apiLogin(email: string, password: string) {
  return request<{ user: UserProfile; token: string }>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function apiGetMe() {
  return request<{ user: UserProfile }>('/auth/me');
}

// Key Management & Directory
export async function apiRegisterKeys(payload: {
  keyId: string;
  version: number;
  dhPublicKey: string;
  signingPublicKey: string;
  signature: string;
}) {
  return request<{ success: boolean; bundle: UserPublicKeyBundle }>('/keys/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function apiGetUserKeyBundle(userId: string) {
  return request<{ bundle: UserPublicKeyBundle }>(`/keys/${userId}`);
}

/**
 * Fetches any key bundle (including revoked/rotated) by its keyId.
 * Essential for verifying signatures on messages sent before a key rotation.
 */
export async function apiGetKeyByKeyId(keyId: string) {
  return request<{ bundle: UserPublicKeyBundle }>(`/keys/by-key-id/${keyId}`);
}

export interface DirectoryUser {
  id: string;
  email: string;
  fullName: string;
  createdAt: string;
  hasKeys: boolean;
  keyId: string | null;
  fingerprint: string | null;
  safetyNumber: string | null;
  dhPublicKey: string | null;
  signingPublicKey: string | null;
}

export async function apiListDirectory() {
  return request<{ directory: DirectoryUser[] }>('/keys/directory');
}

export async function apiRotateKeys(payload: {
  keyId: string;
  version: number;
  dhPublicKey: string;
  signingPublicKey: string;
  signature: string;
}) {
  return request<{ success: boolean; bundleId: string; fingerprint: string }>('/keys/rotate', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

// Encrypted Messaging
export async function apiSendMessage(envelope: EncryptedMessageEnvelope) {
  return request<{
    success: boolean;
    messageId: string;
    conversationId: string;
    status: string;
    payloadSizeBytes: number;
  }>('/messages', {
    method: 'POST',
    body: JSON.stringify(envelope),
  });
}

export interface StoredMessageRecord {
  messageId: string;
  conversationId: string;
  senderId: string;
  recipientId: string;
  senderName: string;
  senderEmail: string;
  recipientName: string;
  recipientEmail: string;
  protocolVersion: string;
  senderKeyId: string;
  recipientKeyId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
  authTag: string;
  signature: string;
  canonicalAAD: string;
  payloadSizeBytes: number;
  deliveryStatus: 'sent' | 'stored_in_cloud' | 'delivered' | 'read';
  timestamp: number;
}

export async function apiGetMessages(query?: { conversationId?: string; participantId?: string }) {
  let endpoint = '/messages';
  const params = new URLSearchParams();
  if (query?.conversationId) params.append('conversationId', query.conversationId);
  if (query?.participantId) params.append('participantId', query.participantId);
  if (params.toString()) endpoint += `?${params.toString()}`;

  return request<{ messages: StoredMessageRecord[] }>(endpoint);
}

export interface ConversationItem {
  id: string;
  participantId: string;
  participantName: string;
  participantEmail: string;
  participantFingerprint: string;
  updatedAt: string;
}

export async function apiGetConversations() {
  return request<{ conversations: ConversationItem[] }>('/messages/conversations');
}

export interface CloudVaultData {
  totalEncryptedMessages: number;
  totalStorageBytes: number;
  storageUsageFormatted: string;
  records: {
    messageId: string;
    senderEmail: string;
    recipientEmail: string;
    protocolVersion: string;
    sizeBytes: number;
    noncePreview: string;
    authTagPreview: string;
    signaturePreview: string;
    deliveryStatus: string;
    createdAt: string;
  }[];
}

export async function apiGetCloudVault() {
  return request<{ vault: CloudVaultData }>('/messages/vault');
}

export async function apiUpdateMessageStatus(id: string, status: 'delivered' | 'read') {
  return request<{ success: boolean; messageId: string; status: string }>(`/messages/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
}

// Security Events
export async function apiGetSecurityEvents() {
  return request<{ events: SecurityEventLog[] }>('/security/events');
}

export async function apiLogSecurityEvent(payload: {
  eventType: string;
  status: 'SUCCESS' | 'WARNING' | 'CRITICAL';
  details: string;
  metadata?: Record<string, unknown>;
}) {
  return request<{ success: boolean; eventId: string }>('/security/events', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}
