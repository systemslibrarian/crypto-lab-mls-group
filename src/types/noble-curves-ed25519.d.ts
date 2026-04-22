declare module '@noble/curves/ed25519.js' {
  export const x25519: {
    getPublicKey: (privateKey: Uint8Array) => Uint8Array;
    getSharedSecret: (privateKey: Uint8Array, publicKey: Uint8Array) => Uint8Array;
  };
}
