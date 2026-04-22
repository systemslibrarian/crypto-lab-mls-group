import { x25519 } from '@noble/curves/ed25519.js';
import { expand, extract } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes, randomBytes, utf8 } from './ciphersuite';

export interface HpkeCiphertext {
  enc: Uint8Array;
  ciphertext: Uint8Array;
}

// RFC 9180 §7.1 — DHKEM(X25519, HKDF-SHA256)  kem_id = 0x0020
const KEM_SUITE_ID = concatBytes(utf8('KEM'), new Uint8Array([0x00, 0x20]));
// RFC 9180 §5.1 — suite_id = "HPKE" || kem_id || kdf_id || aead_id
// kem_id=0x0020, kdf_id=0x0001 (HKDF-SHA256), aead_id=0x0001 (AES-128-GCM)
const HPKE_SUITE_ID = concatBytes(utf8('HPKE'), new Uint8Array([0x00, 0x20, 0x00, 0x01, 0x00, 0x01]));

// RFC 9180 §4 LabeledExtract
function labeledExtract(suiteId: Uint8Array, salt: Uint8Array | undefined, label: string, ikm: Uint8Array): Uint8Array {
  const labeled = concatBytes(utf8('HPKE-v1'), suiteId, utf8(label), ikm);
  return new Uint8Array(extract(sha256, labeled, salt));
}

// RFC 9180 §4 LabeledExpand — uses raw HKDF-Expand, NOT expandWithLabel
function labeledExpand(suiteId: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, length: number): Uint8Array {
  const labeledInfo = concatBytes(
    new Uint8Array([(length >>> 8) & 0xff, length & 0xff]),
    utf8('HPKE-v1'), suiteId, utf8(label), info
  );
  return expand(sha256, prk, labeledInfo, length);
}

async function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const out = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, k, plaintext);
  return new Uint8Array(out);
}

async function aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const out = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, k, ciphertext);
  return new Uint8Array(out);
}

// RFC 9180 §4.1 Encap — ephemeral X25519, DH, KEM shared secret
function kemEncap(recipientPublicKey: Uint8Array): { sharedSecret: Uint8Array; enc: Uint8Array } {
  const ephemeralPrivate = randomBytes(32);
  const enc = x25519.getPublicKey(ephemeralPrivate);
  const dh = x25519.getSharedSecret(ephemeralPrivate, recipientPublicKey);
  const kemContext = concatBytes(enc, recipientPublicKey);
  const eaePrk = labeledExtract(KEM_SUITE_ID, undefined, 'eae_prk', dh);
  const sharedSecret = labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, 32);
  return { sharedSecret, enc };
}

// RFC 9180 §4.1 Decap
function kemDecap(recipientPrivateKey: Uint8Array, enc: Uint8Array): Uint8Array {
  const recipientPublicKey = x25519.getPublicKey(recipientPrivateKey);
  const dh = x25519.getSharedSecret(recipientPrivateKey, enc);
  const kemContext = concatBytes(enc, recipientPublicKey);
  const eaePrk = labeledExtract(KEM_SUITE_ID, undefined, 'eae_prk', dh);
  return labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, 32);
}

// RFC 9180 §5.1 Base mode key schedule
function hpkeKeySchedule(sharedSecret: Uint8Array, info: Uint8Array): { key: Uint8Array; nonce: Uint8Array } {
  const empty = new Uint8Array(0);
  const pskIdHash = labeledExtract(HPKE_SUITE_ID, undefined, 'psk_id_hash', empty);
  const infoHash  = labeledExtract(HPKE_SUITE_ID, undefined, 'info_hash', info);
  // mode = 0x00 (Base)
  const ksContext = concatBytes(new Uint8Array([0x00]), pskIdHash, infoHash);
  const psk = labeledExtract(HPKE_SUITE_ID, undefined, 'psk', empty);
  const secret = labeledExtract(HPKE_SUITE_ID, psk, 'shared_secret', sharedSecret);
  const key   = labeledExpand(HPKE_SUITE_ID, secret, 'key',        ksContext, 16); // Nk=16
  const nonce = labeledExpand(HPKE_SUITE_ID, secret, 'base_nonce', ksContext, 12); // Nn=12
  return { key, nonce };
}

export async function hpkeSeal(recipientPublicKey: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<HpkeCiphertext> {
  const { sharedSecret, enc } = kemEncap(recipientPublicKey);
  const { key, nonce } = hpkeKeySchedule(sharedSecret, aad);
  const ciphertext = await aesGcmEncrypt(key, nonce, aad, plaintext);
  return { enc, ciphertext };
}

export async function hpkeOpen(recipientPrivateKey: Uint8Array, enc: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const sharedSecret = kemDecap(recipientPrivateKey, enc);
  const { key, nonce } = hpkeKeySchedule(sharedSecret, aad);
  return aesGcmDecrypt(key, nonce, aad, ciphertext);
}
