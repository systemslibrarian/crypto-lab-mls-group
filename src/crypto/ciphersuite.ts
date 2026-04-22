export const MLS_CIPHERSUITE = {
  id: 0x0001,
  name: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
  hashLength: 32,
  keyLength: 16,
  nonceLength: 12
} as const;

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, item) => sum + item.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function utf8(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

export function hex(input: Uint8Array): string {
  return Array.from(input)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export async function sha256Digest(input: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', input);
  return new Uint8Array(digest);
}

export function u16be(value: number): Uint8Array {
  return new Uint8Array([(value >>> 8) & 0xff, value & 0xff]);
}
