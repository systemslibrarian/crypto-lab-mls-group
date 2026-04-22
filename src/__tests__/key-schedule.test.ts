import { randomBytes } from '../crypto/ciphersuite';
import { deriveSecret, expandWithLabel } from '../crypto/hkdf';
import { deriveEpochSecrets } from '../group/key-schedule';

function assertEqualBytes(name: string, a: Uint8Array, b: Uint8Array): void {
  if (a.length !== b.length) {
    throw new Error(`${name}: length mismatch`);
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      throw new Error(`${name}: mismatch at ${i}`);
    }
  }
}

export function runKeyScheduleHarness(): string {
  const initSecret = randomBytes(32);
  const commitSecret = randomBytes(32);

  const secrets = deriveEpochSecrets(initSecret, commitSecret);

  const expectedWelcome = deriveSecret(secrets.joiner, 'welcome');
  const expectedEpoch = deriveSecret(secrets.joiner, 'epoch');
  assertEqualBytes('welcome derivation', secrets.welcome, expectedWelcome);
  assertEqualBytes('epoch derivation', secrets.epoch, expectedEpoch);

  assertEqualBytes('sender_data derivation', secrets.sender_data, deriveSecret(secrets.epoch, 'sender data'));
  assertEqualBytes('encryption derivation', secrets.encryption, deriveSecret(secrets.epoch, 'encryption'));
  assertEqualBytes('exporter derivation', secrets.exporter, deriveSecret(secrets.epoch, 'exporter'));
  assertEqualBytes('external derivation', secrets.external, deriveSecret(secrets.epoch, 'external'));
  assertEqualBytes('confirmation derivation', secrets.confirmation, deriveSecret(secrets.epoch, 'confirm'));
  assertEqualBytes('membership derivation', secrets.membership, deriveSecret(secrets.epoch, 'membership'));
  assertEqualBytes('resumption derivation', secrets.resumption, deriveSecret(secrets.epoch, 'resumption'));
  assertEqualBytes('init derivation', secrets.init, deriveSecret(secrets.epoch, 'init'));
  assertEqualBytes('authentication derivation', secrets.authentication, deriveSecret(secrets.epoch, 'authentication'));

  const labelRoundTrip = expandWithLabel(secrets.epoch, 'sender data', new Uint8Array(), 32);
  assertEqualBytes('ExpandWithLabel size', labelRoundTrip, secrets.sender_data);

  return 'key schedule relationships verified';
}
