import { Response } from 'express';
import { z } from 'zod';
import { getDatabase } from '../database/db.js';
import { AuthenticatedRequest } from '../middleware/auth.js';
import {
  verifyRegistrationSignature,
  computeFingerprint,
  computeSafetyNumber,
  base64ToBytes,
} from '../crypto/verifyKeyBundle.js';
import { Request } from 'express';

const registerKeysSchema = z.object({
  keyId: z.string().min(1),
  version: z.number().int().positive().default(1),
  dhPublicKey: z.string().min(10), // Base64 X25519 public key
  signingPublicKey: z.string().min(10), // Base64 Ed25519 public key
  signature: z.string().min(10), // Ed25519 signature
});

export async function registerKeys(req: AuthenticatedRequest, res: Response) {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const parse = registerKeysSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: parse.error.errors[0].message });
      return;
    }

    const { keyId, version, dhPublicKey, signingPublicKey, signature } = parse.data;
    const userId = req.user.userId;

    // Cryptographically verify that the user self-signed this key bundle
    const isValidSignature = verifyRegistrationSignature(
      userId,
      dhPublicKey,
      version,
      signingPublicKey,
      signature
    );

    if (!isValidSignature) {
      res.status(400).json({
        error: 'Cryptographic verification failed: Public key registration bundle signature is invalid',
      });
      return;
    }

    // Compute standardized fingerprint and safety number
    const dhBytes = base64ToBytes(dhPublicKey);
    const sigBytes = base64ToBytes(signingPublicKey);
    const combinedBytes = new Uint8Array([...dhBytes, ...sigBytes]);
    const fingerprint = computeFingerprint(combinedBytes);
    const safetyNumber = computeSafetyNumber(dhBytes, sigBytes);

    const db = await getDatabase();

    // Check if user has active keys and increment or deactivate previous
    await db.execute('UPDATE user_public_keys SET is_revoked = 1 WHERE user_id = ?', [userId]);

    const bundleId = `key_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    await db.execute(
      `INSERT INTO user_public_keys (
        id, user_id, key_id, version, dh_public_key, signing_public_key, signature, fingerprint, safety_number, is_revoked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [
        bundleId,
        userId,
        keyId,
        version,
        dhPublicKey,
        signingPublicKey,
        signature,
        fingerprint,
        safetyNumber,
      ]
    );

    await db.execute(
      'INSERT INTO security_events (id, user_id, event_type, status, details, metadata) VALUES (?, ?, ?, ?, ?, ?)',
      [
        `sec_${Date.now()}`,
        userId,
        'KEY_REGISTERED',
        'SUCCESS',
        `X25519 & Ed25519 Public Keys registered with verified signature. Fingerprint: ${fingerprint}`,
        JSON.stringify({ keyId, version, fingerprint }),
      ]
    );

    res.status(201).json({
      success: true,
      bundle: {
        id: bundleId,
        userId,
        keyId,
        version,
        dhPublicKey,
        signingPublicKey,
        fingerprint,
        safetyNumber,
        isRevoked: false,
      },
    });
  } catch (err: any) {
    console.error('Register keys error:', err);
    res.status(500).json({ error: 'Internal server error during key registration' });
  }
}

export async function getUserKeyBundle(req: AuthenticatedRequest, res: Response) {
  try {
    const { userId } = req.params;
    const db = await getDatabase();

    const rows = await db.query(
      `SELECT k.id, k.user_id, k.key_id, k.version, k.dh_public_key, k.signing_public_key,
              k.signature, k.fingerprint, k.safety_number, k.is_revoked, k.created_at,
              u.email, u.full_name
       FROM user_public_keys k
       JOIN users u ON u.id = k.user_id
       WHERE k.user_id = ? AND k.is_revoked = 0
       ORDER BY k.version DESC LIMIT 1`,
      [userId]
    );

    if (rows.length === 0) {
      res.status(404).json({ error: 'Active public key bundle not found for user' });
      return;
    }

    const row = rows[0];
    res.json({
      bundle: {
        id: row.id,
        userId: row.user_id,
        userEmail: row.email,
        userFullName: row.full_name,
        keyId: row.key_id,
        version: row.version,
        dhPublicKey: row.dh_public_key,
        signingPublicKey: row.signing_public_key,
        signature: row.signature,
        fingerprint: row.fingerprint,
        safetyNumber: row.safety_number,
        isRevoked: Boolean(row.is_revoked),
        createdAt: row.created_at,
      },
    });
  } catch (err: any) {
    console.error('Get user key bundle error:', err);
    res.status(500).json({ error: 'Internal server error fetching key bundle' });
  }
}

export async function listDirectory(req: AuthenticatedRequest, res: Response) {
  try {
    const db = await getDatabase();
    const rows = await db.query(
      `SELECT u.id, u.email, u.full_name, u.created_at,
              k.key_id, k.version, k.dh_public_key, k.signing_public_key, k.fingerprint, k.safety_number
       FROM users u
       LEFT JOIN user_public_keys k ON k.user_id = u.id AND k.is_revoked = 0
       ORDER BY u.full_name ASC`
    );

    res.json({
      directory: rows.map((r) => ({
        id: r.id,
        email: r.email,
        fullName: r.full_name,
        createdAt: r.created_at,
        hasKeys: Boolean(r.dh_public_key),
        keyId: r.key_id || null,
        fingerprint: r.fingerprint || null,
        safetyNumber: r.safety_number || null,
        dhPublicKey: r.dh_public_key || null,
        signingPublicKey: r.signing_public_key || null,
      })),
    });
  } catch (err: any) {
    console.error('Directory list error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

export async function rotateKeys(req: AuthenticatedRequest, res: Response) {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const parse = registerKeysSchema.safeParse(req.body);
    if (!parse.success) {
      res.status(400).json({ error: parse.error.errors[0].message });
      return;
    }

    const { keyId, version, dhPublicKey, signingPublicKey, signature } = parse.data;
    const userId = req.user.userId;

    const isValidSignature = verifyRegistrationSignature(
      userId,
      dhPublicKey,
      version,
      signingPublicKey,
      signature
    );

    if (!isValidSignature) {
      res.status(400).json({ error: 'Invalid key rotation signature' });
      return;
    }

    const dhBytes = base64ToBytes(dhPublicKey);
    const sigBytes = base64ToBytes(signingPublicKey);
    const combinedBytes = new Uint8Array([...dhBytes, ...sigBytes]);
    const fingerprint = computeFingerprint(combinedBytes);
    const safetyNumber = computeSafetyNumber(dhBytes, sigBytes);

    const db = await getDatabase();
    await db.execute('UPDATE user_public_keys SET is_revoked = 1 WHERE user_id = ?', [userId]);

    const bundleId = `key_rot_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    await db.execute(
      `INSERT INTO user_public_keys (
        id, user_id, key_id, version, dh_public_key, signing_public_key, signature, fingerprint, safety_number, is_revoked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [
        bundleId,
        userId,
        keyId,
        version,
        dhPublicKey,
        signingPublicKey,
        signature,
        fingerprint,
        safetyNumber,
      ]
    );

    await db.execute(
      'INSERT INTO security_events (id, user_id, event_type, status, details) VALUES (?, ?, ?, ?, ?)',
      [
        `sec_rot_${Date.now()}`,
        userId,
        'KEY_ROTATED',
        'SUCCESS',
        `Key rotation succeeded. New version: ${version}, Fingerprint: ${fingerprint}`,
      ]
    );

    res.json({
      success: true,
      message: 'Key rotation complete and logged',
      bundleId,
      fingerprint,
    });
  } catch (err: any) {
    console.error('Key rotation error:', err);
    res.status(500).json({ error: 'Internal server error during key rotation' });
  }
}

/**
 * GET /api/keys/by-key-id/:keyId
 * Fetches any key bundle (including revoked) by its keyId.
 * Used by recipients to verify historical message signatures after sender key rotation.
 */
export async function getKeyByKeyId(req: Request, res: Response) {
  try {
    const { keyId } = req.params;
    const db = await getDatabase();

    const rows = await db.query(
      `SELECT k.id, k.user_id, k.key_id, k.version, k.dh_public_key, k.signing_public_key,
              k.signature, k.fingerprint, k.safety_number, k.is_revoked, k.created_at,
              u.email, u.full_name
       FROM user_public_keys k
       JOIN users u ON u.id = k.user_id
       WHERE k.key_id = ?
       LIMIT 1`,
      [keyId]
    );

    if (rows.length === 0) {
      res.status(404).json({ error: 'Key bundle not found for the given keyId' });
      return;
    }

    const row = rows[0];
    res.json({
      bundle: {
        userId: row.user_id,
        userEmail: row.email,
        userFullName: row.full_name,
        keyId: row.key_id,
        version: row.version,
        dhPublicKey: row.dh_public_key,
        signingPublicKey: row.signing_public_key,
        fingerprint: row.fingerprint,
        safetyNumber: row.safety_number,
        isRevoked: Boolean(row.is_revoked),
        createdAt: row.created_at,
      },
    });
  } catch (err: any) {
    console.error('Get key by keyId error:', err);
    res.status(500).json({ error: 'Internal server error fetching key bundle by keyId' });
  }
}
