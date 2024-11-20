import * as validate_error from "./validate_error.js";

export const PRIVATE_KEY_SIZE = 32;
export const PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
export const PUBLIC_KEY_COMPRESSED_SIZE = 33;
export const X_ONLY_PUBLIC_KEY_SIZE = 32;
export const TWEAK_SIZE = 32;
export const SIGNATURE_SIZE = 64;
export const HASH_SIZE = 32;
export const EXTRA_DATA_SIZE = 32;

export function isDERPoint(p: Uint8Array): boolean {
  return (
    p.length === PUBLIC_KEY_COMPRESSED_SIZE ||
    p.length === PUBLIC_KEY_UNCOMPRESSED_SIZE
  );
}

export function isPointCompressed(p: Uint8Array): boolean {
  return p.length === PUBLIC_KEY_COMPRESSED_SIZE;
}

export function isXOnlyPoint(p: Uint8Array): boolean {
  return p.length === X_ONLY_PUBLIC_KEY_SIZE;
}

export function isPrivate(d: Uint8Array): boolean {
  return d.length === PRIVATE_KEY_SIZE;
}

export function isSignature(s: Uint8Array): boolean {
  return s.length === SIGNATURE_SIZE;
}

export function isHash(h: Uint8Array): boolean {
  return h.length === HASH_SIZE;
}

export function isTweak(t: Uint8Array): boolean {
  return t.length === TWEAK_SIZE;
}

export function isExtraData(e: Uint8Array): boolean {
  return e.length === EXTRA_DATA_SIZE;
}

export function isZero(t: Uint8Array): boolean {
  for (let i = 0; i < t.length; i++) {
    if (t[i] !== 0) return false;
  }
  return true;
}

export function validatePrivate(d: Uint8Array): void {
  if (!isPrivate(d)) throw new validate_error.InvalidPrivateKeyError();
}

export function validatePoint(p: Uint8Array): void {
  if (!isDERPoint(p)) throw new validate_error.InvalidPublicKeyError();
}

export function validateXOnlyPoint(p: Uint8Array): void {
  if (!isXOnlyPoint(p)) throw new validate_error.InvalidPublicKeyError();
}

export function validateSignature(s: Uint8Array): void {
  if (!isSignature(s)) throw new validate_error.InvalidSignatureError();
}

export function validateHash(h: Uint8Array): void {
  if (!isHash(h)) throw new validate_error.InvalidHashError();
}

export function validateTweak(t: Uint8Array): void {
  if (!isTweak(t)) throw new validate_error.InvalidTweakError();
}

export function validateExtraData(e?: Uint8Array): void {
  if (e !== undefined && !isExtraData(e))
    throw new validate_error.InvalidExtraDataError();
}

export function validateParity(p: number): void {
  if (p !== 0 && p !== 1) throw new validate_error.InvalidParityError();
}

export function validateSignatureNonzeroRS(sig: Uint8Array): void {
  validateSignatureCustom((): boolean => !isZero(sig.subarray(0, 32)));
  validateSignatureCustom((): boolean => !isZero(sig.subarray(32, 64)));
}

export function validateSigrPMinusN(sig: Uint8Array): void {
  validateSignatureCustom((): boolean => {
    const r = sig.subarray(0, 32);
    const rLen = r.length;
    let carry = 0;
    for (let i = 0; i < rLen; i++) {
      carry = r[i] - SECP256K1_N[i] - carry;
      if (carry < 0) return true;
      if (carry > 0) return false;
    }
    return false;
  });
}

export function validateSignatureCustom(fn: () => boolean): void {
  if (!fn()) throw new validate_error.InvalidSignatureError();
}

const SECP256K1_N = new Uint8Array([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
  0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]);
