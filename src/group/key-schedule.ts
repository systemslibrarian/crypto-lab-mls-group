import { deriveSecret, extractSecret } from '../crypto/hkdf';

export interface EpochSecrets {
  joiner: Uint8Array;
  welcome: Uint8Array;
  epoch: Uint8Array;
  sender_data: Uint8Array;
  encryption: Uint8Array;
  exporter: Uint8Array;
  external: Uint8Array;
  confirmation: Uint8Array;
  membership: Uint8Array;
  resumption: Uint8Array;
  init: Uint8Array;
  authentication: Uint8Array;
}

export function deriveEpochSecrets(initSecret: Uint8Array, commitSecret: Uint8Array): EpochSecrets {
  const joiner = extractSecret(initSecret, commitSecret);
  const welcome = deriveSecret(joiner, 'welcome');
  const epoch = deriveSecret(joiner, 'epoch');

  return {
    joiner,
    welcome,
    epoch,
    sender_data: deriveSecret(epoch, 'sender data'),
    encryption: deriveSecret(epoch, 'encryption'),
    exporter: deriveSecret(epoch, 'exporter'),
    external: deriveSecret(epoch, 'external'),
    confirmation: deriveSecret(epoch, 'confirm'),
    membership: deriveSecret(epoch, 'membership'),
    resumption: deriveSecret(epoch, 'resumption'),
    init: deriveSecret(epoch, 'init'),
    authentication: deriveSecret(epoch, 'authentication')
  };
}
