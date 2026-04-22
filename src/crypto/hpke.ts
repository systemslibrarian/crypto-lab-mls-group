import { x25519 } from '@noble/curves/ed25519.js';
import { concatBytes, randomBytes, utf8 } from './ciphersuite';
import { expandWithLabel, extractSecret } from './hkdf';

export interface HpkeCiphertext {
  enc: Uint8Array;
  ciphertext: Uint8Array;
}

const HPKE_SUITE_ID = concatBytes(utf8('KEM'), new Uint8Array([0, 32]));

function labeledExtract(salt: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  const labeled = concatBytes(utf8('HPKE-v1'), HPKE_SUITE_ID, utf8(label), ikm);
  return extractSecret(salt, labeled);
}

function labeledExpand(prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  const labeledInfo = concatBytes(new Uint8Array([(length >>> 8) & 0xff, length & 0xff]), utf8('HPKE-v1'), HPKE_SUITE_ID, utf8(label), info);
  return expandWithLabel(prk, label, labeledInfo, length);
}

async function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const keyRaw = new Uint8Array(key);
  const iv = new Uint8Array(nonce);
  const add = new Uint8Array(aad);
  const plain = new Uint8Array(plaintext);
  const k = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['encrypt']);
  const out = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: add }, k, plain);
  return new Uint8Array(out);
}

async function aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const keyRaw = new Uint8Array(key);
  const iv = new Uint8Array(nonce);
  const add = new Uint8Array(aad);
  const cipher = new Uint8Array(ciphertext);
  const k = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
  const out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: add }, k, cipher);
  return new Uint8Array(out);
}

export async function hpkeSeal(recipientPublicKey: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<HpkeCiphertext> {
  const ephemeralPrivate = randomBytes(32);
  const enc = x25519.getPublicKey(ephemeralPrivate);
  const shared = x25519.getSharedSecret(ephemeralPrivate, recipientPublicKey);
  const kemContext = concatBytes(enc, recipientPublicKey);
  const eaePrk = labeledExtract(new Uint8Array(), 'eae_prk', shared);
  const secret = labeledExpand(eaePrk, 'shared_secret', kemContext, 32);
  const key = expandWithLabel(secret, 'hpke key', new Uint8Array(), 16);
  const nonce = expandWithLabel(secret, 'hpke nonce', new Uint8Array(), 12);
  const ciphertext = await aesGcmEncrypt(key, nonce, aad, plaintext);
  return { enc, ciphertext };
}

export async function hpkeOpen(recipientPrivateKey: Uint8Array, enc: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const recipientPublicKey = x25519.getPublicKey(recipientPrivateKey);
  const shared = x25519.getSharedSecret(recipientPrivateKey, enc);
  const kemContext = concatBytes(enc, recipientPublicKey);
  const eaePrk = labeledExtract(new Uint8Array(), 'eae_prk', shared);
  const secret = labeledExpand(eaePrk, 'shared_secret', kemContext, 32);
  const key = expandWithLabel(secret, 'hpke key', new Uint8Array(), 16);
  const nonce = expandWithLabel(secret, 'hpke nonce', new Uint8Array(), 12);
  return aesGcmDecrypt(key, nonce, aad, ciphertext);
}
