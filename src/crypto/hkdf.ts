import { expand, extract } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { MLS_CIPHERSUITE, concatBytes, u16be, utf8 } from './ciphersuite';

export function expandWithLabel(secret: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array {
  const fullLabel = utf8(`MLS 1.0 ${label}`);
  if (fullLabel.length > 255 || context.length > 255) {
    throw new Error('HKDF label/context too long for MLS vector encoding');
  }

  const hkdfLabel = concatBytes(
    u16be(length),
    new Uint8Array([fullLabel.length]),
    fullLabel,
    new Uint8Array([context.length]),
    context
  );

  return expand(sha256, secret, hkdfLabel, length);
}

export function deriveSecret(secret: Uint8Array, label: string): Uint8Array {
  return expandWithLabel(secret, label, new Uint8Array(), MLS_CIPHERSUITE.hashLength);
}

export function extractSecret(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return extract(sha256, ikm, salt);
}
