import { concatBytes, hex, utf8 } from '../crypto/ciphersuite';
import { hpkeSeal } from '../crypto/hpke';
import { deriveSecret, expandWithLabel } from '../crypto/hkdf';
import { RatchetTree } from '../tree/ratchet-tree';

export interface GroupSecrets {
  joinerSecret: Uint8Array;
  pathSecret: Uint8Array;
  psks: Uint8Array[];
}

export interface WelcomeMessage {
  encryptedGroupSecrets: Array<{ memberLeaf: number; enc: Uint8Array; ciphertext: Uint8Array }>;
  encryptedGroupInfo: Uint8Array;
  nonce: Uint8Array;
}

async function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const keyRaw = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength);
  const iv = nonce.buffer.slice(nonce.byteOffset, nonce.byteOffset + nonce.byteLength);
  const add = aad.buffer.slice(aad.byteOffset, aad.byteOffset + aad.byteLength);
  const plain = plaintext.buffer.slice(plaintext.byteOffset, plaintext.byteOffset + plaintext.byteLength);
  const k = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['encrypt']);
  const out = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: add }, k, plain);
  return new Uint8Array(out);
}

export async function buildWelcome(tree: RatchetTree, newLeaves: number[], groupSecrets: GroupSecrets, groupInfo: Uint8Array): Promise<WelcomeMessage> {
  const encryptedGroupSecrets: Array<{ memberLeaf: number; enc: Uint8Array; ciphertext: Uint8Array }> = [];

  for (const leaf of newLeaves) {
    const leafNode = tree.nodes.get(leaf)?.leafNode;
    if (!leafNode) {
      continue;
    }
    const payload = concatBytes(groupSecrets.joinerSecret, groupSecrets.pathSecret, ...groupSecrets.psks);
    const sealed = await hpkeSeal(leafNode.hpkePublicKey, utf8('mls-welcome'), payload);
    encryptedGroupSecrets.push({ memberLeaf: leaf, enc: sealed.enc, ciphertext: sealed.ciphertext });
  }

  const welcomeSecret = deriveSecret(groupSecrets.joinerSecret, 'welcome');
  const welcomeKey = expandWithLabel(welcomeSecret, 'key', new Uint8Array(), 16);
  const welcomeNonce = expandWithLabel(welcomeSecret, 'nonce', new Uint8Array(), 12);
  const encryptedGroupInfo = await aesGcmEncrypt(welcomeKey, welcomeNonce, utf8('group-info'), groupInfo);

  return {
    encryptedGroupSecrets,
    encryptedGroupInfo,
    nonce: welcomeNonce
  };
}

export function describeWelcome(message: WelcomeMessage): string {
  return `Welcome secrets: ${message.encryptedGroupSecrets.length}, group info tag: ${hex(message.encryptedGroupInfo.slice(-16))}`;
}
