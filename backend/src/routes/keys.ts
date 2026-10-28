import { Router } from 'express';
import {
  registerKeys,
  getUserKeyBundle,
  listDirectory,
  rotateKeys,
  getKeyByKeyId,
} from '../controllers/keysController.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

router.post('/register', requireAuth, registerKeys);
router.post('/rotate', requireAuth, rotateKeys);
router.get('/directory', requireAuth, listDirectory);
router.get('/by-key-id/:keyId', requireAuth, getKeyByKeyId);
router.get('/:userId', requireAuth, getUserKeyBundle);

export default router;
