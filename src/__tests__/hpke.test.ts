import { afterEach, describe, expect, it, vi } from 'vitest';
import * as bytes from '../crypto/ciphersuite';
import { hpkeKeySchedule, hpkeOpen, hpkeSeal } from '../crypto/hpke';

const fromHex = (value: string) => new Uint8Array(value.match(/../g)!.map((b) => parseInt(b, 16)));

// RFC 9180 Appendix A.1.1 / A.1.1.1, sequence 0:
// https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.1
const info = fromHex('4f6465206f6e2061204772656369616e2055726e');
const skE = fromHex('52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736');
const skR = fromHex('4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8');
const pkR = fromHex('3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d');
const enc = fromHex('37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431');
const sharedSecret = fromHex('fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc');
const aad = fromHex('436f756e742d30');
const pt = fromHex('4265617574792069732074727574682c20747275746820626561757479');
const ct = fromHex('f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a');

afterEach(() => vi.restoreAllMocks());

describe('HPKE base mode RFC 9180 published vector', () => {
  it('derives the published key and base nonce from the KEM shared secret', () => {
    const { key, nonce } = hpkeKeySchedule(sharedSecret, info);
    expect(bytes.hex(key)).toBe('4531685d41d65f03dc48f6b8302c05b0');
    expect(bytes.hex(nonce)).toBe('56d890e5accaaf011cff4b7d');
  });

  it('seals the published ciphertext through Noble X25519 and WebCrypto', async () => {
    // Deterministic ephemeral private key only inside this test.
    const random = vi.spyOn(bytes, 'randomBytes').mockReturnValue(skE);
    const sealed = await hpkeSeal(pkR, aad, pt, info);
    expect(random).toHaveBeenCalledWith(32);
    expect(sealed.enc).toEqual(enc);
    expect(sealed.ciphertext).toEqual(ct);
  });

  it('opens the independently published ciphertext', async () => {
    expect(await hpkeOpen(skR, enc, aad, ct, info)).toEqual(pt);
  });

  it('rejects wrong AAD with the original info held fixed', async () => {
    await expect(hpkeOpen(skR, enc, bytes.utf8('wrong AAD'), ct, info)).rejects.toThrow();
  });

  it('rejects a modified authentication tag', async () => {
    const changed = ct.slice();
    changed[changed.length - 1] ^= 1;
    await expect(hpkeOpen(skR, enc, aad, changed, info)).rejects.toThrow();
  });

  it('rejects wrong key-schedule info', async () => {
    await expect(hpkeOpen(skR, enc, aad, ct, bytes.utf8('wrong info'))).rejects.toThrow();
  });

  it('preserves the MLS shorthand that uses AAD as info', async () => {
    const sealed = await hpkeSeal(pkR, aad, pt);
    expect(await hpkeOpen(skR, sealed.enc, aad, sealed.ciphertext)).toEqual(pt);
    expect(await hpkeOpen(skR, sealed.enc, aad, sealed.ciphertext, aad)).toEqual(pt);
  });
});
