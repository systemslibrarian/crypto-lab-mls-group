import { describe, it, expect } from 'vitest';
import { randomBytes } from '../crypto/ciphersuite';
import { deriveSecret, expandWithLabel } from '../crypto/hkdf';
import { deriveEpochSecrets } from '../group/key-schedule';

const hex = (a: Uint8Array) => Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join('');

describe('key schedule (RFC 9420 §8)', () => {
  it('derives each epoch secret with the correct label from epoch_secret', () => {
    const secrets = deriveEpochSecrets(randomBytes(32), randomBytes(32));

    expect(hex(secrets.welcome)).toBe(hex(deriveSecret(secrets.joiner, 'welcome')));
    expect(hex(secrets.epoch)).toBe(hex(deriveSecret(secrets.joiner, 'epoch')));
    expect(hex(secrets.sender_data)).toBe(hex(deriveSecret(secrets.epoch, 'sender data')));
    expect(hex(secrets.encryption)).toBe(hex(deriveSecret(secrets.epoch, 'encryption')));
    expect(hex(secrets.exporter)).toBe(hex(deriveSecret(secrets.epoch, 'exporter')));
    expect(hex(secrets.confirmation)).toBe(hex(deriveSecret(secrets.epoch, 'confirm')));
    expect(hex(secrets.init)).toBe(hex(deriveSecret(secrets.epoch, 'init')));
  });

  it('is deterministic for fixed inputs and changes when commit_secret changes', () => {
    const init = randomBytes(32);
    const commit = randomBytes(32);
    expect(hex(deriveEpochSecrets(init, commit).epoch)).toBe(hex(deriveEpochSecrets(init, commit).epoch));
    expect(hex(deriveEpochSecrets(init, commit).epoch)).not.toBe(hex(deriveEpochSecrets(init, randomBytes(32)).epoch));
  });

  it('ExpandWithLabel produces the requested length and rejects oversized labels', () => {
    expect(expandWithLabel(randomBytes(32), 'key', new Uint8Array(), 16)).toHaveLength(16);
    expect(() => expandWithLabel(randomBytes(32), 'x'.repeat(260), new Uint8Array(), 16)).toThrow();
  });
});
