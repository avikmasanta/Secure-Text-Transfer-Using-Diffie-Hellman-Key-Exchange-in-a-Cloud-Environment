import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  Send,
  Lock,
  ShieldCheck,
  ShieldAlert,
  Info,
  Bug,
  Key,
  User,
  CheckCheck,
  Clock,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext.js';
import {
  apiGetConversations,
  apiGetMessages,
  apiSendMessage,
  apiGetUserKeyBundle,
  apiListDirectory,
  apiGetKeyByKeyId,
  ConversationItem,
  StoredMessageRecord,
  DirectoryUser,
} from '../services/api.js';
import {
  prepareAndEncryptMessage,
  verifyAndDecryptMessage,
} from '../crypto/secureMessenger.js';
import { SecurityInspectorModal } from '../components/SecurityInspectorModal.js';
import { TamperSimulatorModal } from '../components/TamperSimulatorModal.js';

interface DecryptedChatBubble {
  record: StoredMessageRecord;
  plaintext: string;
  isMine: boolean;
  isDecrypted: boolean;
  decryptionError?: string;
  signatureWarning?: string;
  fingerprint: string;
}

export const Dashboard: React.FC = () => {
  const { user, clientKeys } = useAuth();

  const [conversations, setConversations] = useState<ConversationItem[]>([]);
  const [activeParticipant, setActiveParticipant] = useState<DirectoryUser | null>(null);
  const [directory, setDirectory] = useState<DirectoryUser[]>([]);
  const [messages, setMessages] = useState<DecryptedChatBubble[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [newText, setNewText] = useState('');
  const [isSending, setIsSending] = useState(false);

  // Cache for signing public keys looked up by keyId (avoids repeated API calls)
  const signingKeyCache = useRef<Map<string, string>>(new Map());

  // Modals state
  const [inspectedMessage, setInspectedMessage] = useState<StoredMessageRecord | null>(null);
  const [tamperedMessage, setTamperedMessage] = useState<StoredMessageRecord | null>(null);

  // Load conversations and directory
  const loadInitialData = async () => {
    try {
      const [convRes, dirRes] = await Promise.all([
        apiGetConversations(),
        apiListDirectory(),
      ]);

      setConversations(convRes.conversations);
      // Filter out self from directory
      const peers = dirRes.directory.filter((d) => d.id !== user?.id);
      setDirectory(peers);

      // Default to first conversation or first peer
      if (!activeParticipant && peers.length > 0) {
        if (convRes.conversations.length > 0) {
          const firstConv = convRes.conversations[0];
          const peer = peers.find((p) => p.id === firstConv.participantId) || peers[0];
          setActiveParticipant(peer);
        } else {
          setActiveParticipant(peers[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, [user]);

  // Load and decrypt messages for active participant
  const loadMessages = async () => {
    if (!activeParticipant || !clientKeys) return;

    try {
      const res = await apiGetMessages({ participantId: activeParticipant.id });

      // Pre-fetch any missing signing keys for messages in this conversation
      // We look up by senderKeyId so we get the exact key used for signing (even revoked ones)
      const missingKeyIds = new Set<string>();
      for (const record of res.messages) {
        if (record.senderId !== user?.id && !signingKeyCache.current.has(record.senderKeyId)) {
          missingKeyIds.add(record.senderKeyId);
        }
      }

      // Fetch unknown key bundles (batch, parallel)
      await Promise.all(
        Array.from(missingKeyIds).map(async (keyId) => {
          try {
            const { bundle } = await apiGetKeyByKeyId(keyId);
            signingKeyCache.current.set(keyId, bundle.signingPublicKey);
          } catch {
            // Key not found - fall back to current participant key
            if (activeParticipant.signingPublicKey) {
              signingKeyCache.current.set(keyId, activeParticipant.signingPublicKey);
            }
          }
        })
      );

      const decryptedList: DecryptedChatBubble[] = res.messages.map((record) => {
        const isMine = record.senderId === user?.id;

        if (isMine) {
          // Sent messages: the sender encrypted for the recipient so they cannot
          // re-derive the same shared secret without the ephemeral private key (which was zeroized).
          // Display a clear informational placeholder instead.
          return {
            record,
            plaintext: '🔒 (Your encrypted message — stored securely in cloud)',
            isMine: true,
            isDecrypted: true,
            fingerprint: activeParticipant.fingerprint || '',
          };
        }

        // --- Received message: full cryptographic verification + decryption ---
        try {
          // Resolve the exact signing public key used when this message was signed
          const signingPubKey =
            signingKeyCache.current.get(record.senderKeyId) ||
            activeParticipant.signingPublicKey ||
            '';

          const decrypted = verifyAndDecryptMessage(
            clientKeys,
            signingPubKey,
            {
              messageId: record.messageId,
              senderId: record.senderId,
              recipientId: record.recipientId,
              protocolVersion: record.protocolVersion,
              senderKeyId: record.senderKeyId,
              recipientKeyId: record.recipientKeyId,
              ephemeralPublicKey: record.ephemeralPublicKey,
              nonce: record.nonce,
              ciphertext: record.ciphertext,
              authTag: record.authTag,
              signature: record.signature,
              canonicalAAD: record.canonicalAAD,
              timestamp: record.timestamp,
              deliveryStatus: record.deliveryStatus,
            },
            true // allow replay for stored messages
          );

          return {
            record,
            plaintext: decrypted.plaintext,
            isMine: false,
            isDecrypted: true,
            fingerprint: activeParticipant.fingerprint || '',
          };
        } catch (decErr: any) {
          const errMsg: string = decErr.message || '';

          // Distinguish between a signature problem and an AES-GCM failure
          const isSigFailure = errMsg.includes('Signature Verification Failed') ||
                               errMsg.includes('forged, altered');
          const isGcmFailure = errMsg.includes('ghash tag') ||
                               errMsg.includes('authentication tag mismatch') ||
                               errMsg.includes('tampering detected');

          let displayError: string;
          if (isSigFailure) {
            displayError = '⚠ Sender key has changed since this message was sent. Signature cannot be verified with current key.';
          } else if (isGcmFailure) {
            displayError = '⚠ Decryption failed: Your private key does not match the recipient key used to encrypt this message. This may happen after key rotation or when accessing from a new device.';
          } else {
            displayError = `⚠ ${errMsg}`;
          }

          return {
            record,
            plaintext: '[CRYPTOGRAPHIC INTEGRITY FAILURE: Message Tampered or Invalid Signature]',
            isMine: false,
            isDecrypted: false,
            decryptionError: displayError,
            fingerprint: activeParticipant.fingerprint || '',
          };
        }
      });

      setMessages(decryptedList);
    } catch (err) {
      console.error('Failed to load messages:', err);
    }
  };

  useEffect(() => {
    loadMessages();
    const interval = setInterval(loadMessages, 5000); // Polling for new messages
    return () => clearInterval(interval);
  }, [activeParticipant, clientKeys]);

  // Send an End-to-End Encrypted Message
  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newText.trim() || !activeParticipant || !clientKeys || isSending) return;

    if (!activeParticipant.dhPublicKey || !activeParticipant.signingPublicKey) {
      alert('Recipient has not yet registered cryptographic public keys. Ask them to log in first.');
      return;
    }

    setIsSending(true);
    try {
      // 1. Client-Side X25519 + HKDF-SHA-256 + AES-256-GCM + Ed25519 Signature
      const encryptedEnvelope = prepareAndEncryptMessage(
        clientKeys,
        {
          userId: activeParticipant.id,
          keyId: activeParticipant.keyId || 'key_default',
          dhPublicKey: activeParticipant.dhPublicKey,
          signingPublicKey: activeParticipant.signingPublicKey,
        },
        newText.trim()
      );

      // 2. Upload strictly ciphertext envelope to cloud storage
      await apiSendMessage(encryptedEnvelope);

      // Clear input and reload
      setNewText('');
      await loadMessages();
      await loadInitialData();
    } catch (err: any) {
      alert(`Encryption / Send Error: ${err.message}`);
    } finally {
      setIsSending(false);
    }
  };

  // Filter conversations/directory
  const filteredPeers = directory.filter(
    (p) =>
      p.fullName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', height: 'calc(100vh - 65px)', backgroundColor: '#ffffff' }}>
      {/* Left Chat Sidebar (Conversations / Contacts) */}
      <div
        style={{
          width: '320px',
          borderRight: '1px solid var(--border-light)',
          display: 'flex',
          flexDirection: 'column',
          backgroundColor: '#ffffff',
        }}
      >
        {/* Search Bar */}
        <div style={{ padding: '1rem', borderBottom: '1px solid var(--border-light)' }}>
          <div style={{ position: 'relative' }}>
            <Search
              size={16}
              style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
            />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search verified contacts..."
              className="input-field"
              style={{ paddingLeft: '2.25rem' }}
            />
          </div>
        </div>

        {/* Contact List */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <div style={{ padding: '0.75rem 1rem 0.25rem', fontSize: '0.6875rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase' }}>
            Registered Users ({filteredPeers.length})
          </div>
          {filteredPeers.length === 0 ? (
            <div style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              No contacts found
            </div>
          ) : (
            filteredPeers.map((peer) => {
              const isSelected = activeParticipant?.id === peer.id;
              return (
                <div
                  key={peer.id}
                  onClick={() => setActiveParticipant(peer)}
                  style={{
                    padding: '0.875rem 1rem',
                    borderBottom: '1px solid #f1f5f9',
                    cursor: 'pointer',
                    backgroundColor: isSelected ? '#eff6ff' : 'transparent',
                    borderLeft: isSelected ? '4px solid #2563eb' : '4px solid transparent',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ fontWeight: 600, fontSize: '0.875rem', color: '#0f172a' }}>
                      {peer.fullName}
                    </div>
                    {peer.hasKeys ? (
                      <span className="badge badge-green" style={{ fontSize: '0.625rem' }}>
                        <Lock size={10} /> Verified
                      </span>
                    ) : (
                      <span className="badge badge-amber" style={{ fontSize: '0.625rem' }}>
                        Pending Keys
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                    {peer.email}
                  </div>
                  {peer.fingerprint && (
                    <div style={{ fontSize: '0.625rem', color: '#2563eb', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                      FP: {peer.fingerprint.substring(0, 14)}...
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Main Conversation Pane */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', backgroundColor: '#f8fafc' }}>
        {activeParticipant ? (
          <>
            {/* Active Chat Header */}
            <div
              style={{
                padding: '0.875rem 1.5rem',
                backgroundColor: '#ffffff',
                borderBottom: '1px solid var(--border-light)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div
                  style={{
                    width: '40px',
                    height: '40px',
                    borderRadius: '50%',
                    backgroundColor: '#dbeafe',
                    color: '#1e40af',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                  }}
                >
                  {activeParticipant.fullName.substring(0, 2).toUpperCase()}
                </div>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.9375rem', color: '#0f172a' }}>
                    {activeParticipant.fullName}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                    <span>{activeParticipant.email}</span>
                    <span>•</span>
                    <span style={{ color: '#16a34a', fontWeight: 500 }}>E2EE Channel Established</span>
                  </div>
                </div>
              </div>

              {/* Header Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {activeParticipant.fingerprint && (
                  <div className="mono-tag" style={{ fontSize: '0.6875rem', color: '#475569' }}>
                    Safety Number: {activeParticipant.safetyNumber ? activeParticipant.safetyNumber.substring(0, 15) + '...' : 'Available'}
                  </div>
                )}
              </div>
            </div>

            {/* Messages Area */}
            <div style={{ flex: 1, padding: '1.5rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Channel Security Banner */}
              <div
                style={{
                  alignSelf: 'center',
                  padding: '0.5rem 1rem',
                  backgroundColor: '#eff6ff',
                  border: '1px solid #bfdbfe',
                  borderRadius: '9999px',
                  fontSize: '0.75rem',
                  color: '#1e40af',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}
              >
                <Lock size={12} />
                Messages are protected with X25519 Diffie–Hellman and AES-256-GCM. Cloud stores only ciphertext.
              </div>

              {messages.length === 0 ? (
                <div style={{ textAlign: 'center', marginTop: '3rem', color: 'var(--text-muted)' }}>
                  <div style={{ width: '48px', height: '48px', borderRadius: '50%', backgroundColor: '#e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 1rem', color: '#64748b' }}>
                    <Lock size={24} />
                  </div>
                  <h4 style={{ fontWeight: 600, color: '#334155' }}>No messages yet</h4>
                  <p style={{ fontSize: '0.8125rem', marginTop: '0.25rem' }}>
                    Send an end-to-end encrypted message to start the secure conversation.
                  </p>
                </div>
              ) : (
                messages.map((item) => (
                  <div
                    key={item.record.messageId}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: item.isMine ? 'flex-end' : 'flex-start',
                    }}
                  >
                    <div
                      style={{
                        maxWidth: '70%',
                        padding: '0.875rem 1rem',
                        borderRadius: item.isMine ? '1rem 1rem 0.25rem 1rem' : '1rem 1rem 1rem 0.25rem',
                        backgroundColor: item.isMine
                          ? '#2563eb'
                          : item.isDecrypted
                          ? '#ffffff'
                          : '#fee2e2',
                        color: item.isMine ? '#ffffff' : item.isDecrypted ? '#0f172a' : '#991b1b',
                        boxShadow: 'var(--shadow-sm)',
                        border: item.isMine ? 'none' : '1px solid var(--border-light)',
                      }}
                    >
                      {/* Message Content */}
                      <div style={{ fontSize: '0.875rem', wordBreak: 'break-word', lineHeight: 1.4 }}>
                        {item.plaintext}
                      </div>

                      {/* Decryption Failure Warning */}
                      {!item.isDecrypted && (
                        <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <AlertTriangle size={14} /> {item.decryptionError}
                        </div>
                      )}

                      {/* Bubble Footer & Actions */}
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: '1rem',
                          marginTop: '0.5rem',
                          fontSize: '0.6875rem',
                          color: item.isMine ? 'rgba(255,255,255,0.75)' : 'var(--text-muted)',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                          <Clock size={10} />
                          <span>{new Date(item.record.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          {/* Inspector Button */}
                          <button
                            onClick={() => setInspectedMessage(item.record)}
                            title="Inspect Cryptographic Envelope"
                            style={{
                              background: 'none',
                              border: 'none',
                              cursor: 'pointer',
                              color: item.isMine ? '#ffffff' : '#2563eb',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.125rem',
                              fontSize: '0.6875rem',
                              fontWeight: 600,
                            }}
                          >
                            <Info size={12} /> Inspect
                          </button>

                          {/* Tamper Simulation Button */}
                          <button
                            onClick={() => setTamperedMessage(item.record)}
                            title="Test Tampering with this message"
                            style={{
                              background: 'none',
                              border: 'none',
                              cursor: 'pointer',
                              color: item.isMine ? '#ffffff' : '#dc2626',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '0.125rem',
                              fontSize: '0.6875rem',
                              fontWeight: 600,
                            }}
                          >
                            <Bug size={12} /> Tamper Test
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Delivery Status Indicator */}
                    <div style={{ fontSize: '0.6875rem', color: '#94a3b8', marginTop: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <CheckCheck size={12} color="#16a34a" />
                      <span>Zero-Knowledge Cloud Stored</span>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Input Bar */}
            <div style={{ padding: '1rem 1.5rem', backgroundColor: '#ffffff', borderTop: '1px solid var(--border-light)' }}>
              <form onSubmit={handleSendMessage} style={{ display: 'flex', gap: '0.75rem' }}>
                <input
                  type="text"
                  value={newText}
                  onChange={(e) => setNewText(e.target.value)}
                  placeholder={`Send encrypted message to ${activeParticipant.fullName}...`}
                  className="input-field"
                  style={{ flex: 1 }}
                  disabled={isSending}
                />
                <button
                  type="submit"
                  disabled={isSending || !newText.trim()}
                  className="btn btn-primary"
                  style={{ padding: '0.625rem 1.25rem' }}
                >
                  {isSending ? (
                    'Encrypting...'
                  ) : (
                    <>
                      <Send size={16} /> Send Encrypted
                    </>
                  )}
                </button>
              </form>
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
            Select a verified participant from the sidebar to open the encrypted conversation.
          </div>
        )}
      </div>

      {/* Modals */}
      <SecurityInspectorModal message={inspectedMessage} onClose={() => setInspectedMessage(null)} />
      <TamperSimulatorModal
        message={tamperedMessage}
        onClose={() => setTamperedMessage(null)}
        onTamperSimulated={() => loadMessages()}
      />
    </div>
  );
};
