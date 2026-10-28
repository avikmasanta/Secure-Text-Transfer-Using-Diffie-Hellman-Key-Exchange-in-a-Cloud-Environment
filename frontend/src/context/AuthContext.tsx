import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserProfile } from '@securetext/shared';
import {
  apiLogin,
  apiRegister,
  apiGetMe,
  apiRegisterKeys,
  apiRotateKeys,
  setStoredToken,
  clearStoredToken,
  getStoredToken,
} from '../services/api.js';
import {
  ClientKeyBundle,
  createClientKeyBundle,
  saveKeysToStorage,
  loadKeysFromStorage,
} from '../crypto/keyManagement.js';
import { bytesToBase64 } from '../crypto/utils.js';

interface AuthContextType {
  user: UserProfile | null;
  clientKeys: ClientKeyBundle | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, fullName: string, password: string) => Promise<void>;
  rotateMyKeys: () => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [clientKeys, setClientKeys] = useState<ClientKeyBundle | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Initialize and check existing session
  useEffect(() => {
    async function initAuth() {
      const token = getStoredToken();
      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        const { user: profile } = await apiGetMe();
        setUser(profile);

        // Try to load existing keys from persistent storage first
        let keys = loadKeysFromStorage(profile.id);

        if (!keys) {
          // No existing keys found anywhere — generate a fresh bundle for this device
          console.log('[Crypto] No keys found in storage. Generating new X25519 & Ed25519 identity key bundle...');
          keys = createClientKeyBundle(profile.id, 1);
          await saveKeysToStorage(keys);

          // Register new public keys with server
          await apiRegisterKeys({
            keyId: keys.keyId,
            version: keys.version,
            dhPublicKey: bytesToBase64(keys.dhKeys.publicKey),
            signingPublicKey: bytesToBase64(keys.signingKeys.publicKey),
            signature: keys.registrationSignature,
          });
          console.log('[Crypto] New keys registered with server. KeyId:', keys.keyId);
        } else {
          // Keys found — re-use them. Re-sync to storage to refresh TTL.
          console.log('[Crypto] Loaded existing keys from storage. KeyId:', keys.keyId);
          await saveKeysToStorage(keys);
        }

        setClientKeys(keys);
      } catch (err) {
        console.warn('Session verification failed, clearing token:', err);
        clearStoredToken();
        setUser(null);
        setClientKeys(null);
      } finally {
        setIsLoading(false);
      }
    }

    initAuth();
  }, []);

  const login = async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const { user: profile, token } = await apiLogin(email, password);
      setStoredToken(token);
      setUser(profile);

      // ALWAYS check persistent storage first — never regenerate if keys exist
      let keys = loadKeysFromStorage(profile.id);
      if (!keys) {
        // First login on this device — generate and register fresh keys
        console.log('[Crypto] First login on this device. Generating new key bundle...');
        keys = createClientKeyBundle(profile.id, 1);
        await saveKeysToStorage(keys);

        await apiRegisterKeys({
          keyId: keys.keyId,
          version: keys.version,
          dhPublicKey: bytesToBase64(keys.dhKeys.publicKey),
          signingPublicKey: bytesToBase64(keys.signingKeys.publicKey),
          signature: keys.registrationSignature,
        });
        console.log('[Crypto] Keys registered with server. KeyId:', keys.keyId);
      } else {
        // Returning login — reuse existing keys so old messages remain decryptable
        console.log('[Crypto] Reusing existing keys from storage. KeyId:', keys.keyId);
        await saveKeysToStorage(keys); // re-sync storage
      }

      setClientKeys(keys);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (email: string, fullName: string, password: string) => {
    setIsLoading(true);
    try {
      const { user: profile, token } = await apiRegister(email, fullName, password);
      setStoredToken(token);
      setUser(profile);

      // Generate initial client key bundle
      const keys = createClientKeyBundle(profile.id, 1);
      await saveKeysToStorage(keys);

      await apiRegisterKeys({
        keyId: keys.keyId,
        version: keys.version,
        dhPublicKey: bytesToBase64(keys.dhKeys.publicKey),
        signingPublicKey: bytesToBase64(keys.signingKeys.publicKey),
        signature: keys.registrationSignature,
      });

      setClientKeys(keys);
    } finally {
      setIsLoading(false);
    }
  };

  const rotateMyKeys = async () => {
    if (!user || !clientKeys) throw new Error('User not authenticated');
    const newVersion = clientKeys.version + 1;
    const newKeys = createClientKeyBundle(user.id, newVersion);

    await apiRotateKeys({
      keyId: newKeys.keyId,
      version: newVersion,
      dhPublicKey: bytesToBase64(newKeys.dhKeys.publicKey),
      signingPublicKey: bytesToBase64(newKeys.signingKeys.publicKey),
      signature: newKeys.registrationSignature,
    });

    await saveKeysToStorage(newKeys);
    setClientKeys(newKeys);
  };

  const logout = () => {
    clearStoredToken();
    setUser(null);
    setClientKeys(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        clientKeys,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        rotateMyKeys,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
