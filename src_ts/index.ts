import * as validate from "./validate.js";
import wasmModule from "./wasm.js";
import * as validate_error from "./validate_error.js";
import * as rand from "./rand.js";
import Memory from "./memory.js";
import { Secp256k1WASM } from "./types.js";
const imports = {
  "./rand.js": rand,
  "./validate_error.js": validate_error,
};
let wasm = {} as unknown as Secp256k1WASM;
let memory = {} as unknown as Memory;

try {
  wasm = new WebAssembly.Instance(new WebAssembly.Module(wasmModule), imports)
    .exports as unknown as Secp256k1WASM;
  memory = new Memory(wasm);
} catch (_) {
  WebAssembly.compile(wasmModule).then((wasmModule) =>
    WebAssembly.instantiate(wasmModule, imports).then((instance) => {
      wasm = instance.exports as unknown as Secp256k1WASM;
      memory = new Memory(wasm);
    })
  );
}

function assumeCompression(compressed?: boolean, p?: Uint8Array): number {
  if (compressed === undefined) {
    return p !== undefined ? p.length : validate.PUBLIC_KEY_COMPRESSED_SIZE;
  }
  return compressed
    ? validate.PUBLIC_KEY_COMPRESSED_SIZE
    : validate.PUBLIC_KEY_UNCOMPRESSED_SIZE;
}

function _isPoint(p: Uint8Array): boolean {
  try {
    memory.PUBLIC_KEY_INPUT.set(p);
    return wasm.isPoint(p.length) === 1;
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function __initializeContext(): void {
  wasm.initializeContext();
}

export function isPoint(p: Uint8Array): boolean {
  return validate.isDERPoint(p) && _isPoint(p);
}

export function isPointCompressed(p: Uint8Array): boolean {
  return validate.isPointCompressed(p) && _isPoint(p);
}

export function isXOnlyPoint(p: Uint8Array): boolean {
  return validate.isXOnlyPoint(p) && _isPoint(p);
}

export function isPrivate(d: Uint8Array): boolean {
  return validate.isPrivate(d);
}

export function pointAdd(
  pA: Uint8Array,
  pB: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(pA);
  validate.validatePoint(pB);
  const outputlen = assumeCompression(compressed, pA);
  try {
    memory.PUBLIC_KEY_INPUT.set(pA);
    memory.PUBLIC_KEY_INPUT2.set(pB);
    return wasm.pointAdd(pA.length, pB.length, outputlen) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
    memory.PUBLIC_KEY_INPUT2.fill(0);
  }
}

export function pointAddScalar(
  p: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(p);
  validate.validateTweak(tweak);
  const outputlen = assumeCompression(compressed, p);
  try {
    memory.PUBLIC_KEY_INPUT.set(p);
    memory.TWEAK_INPUT.set(tweak);
    return wasm.pointAddScalar(p.length, outputlen) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export function pointCompress(p: Uint8Array, compressed?: boolean): Uint8Array {
  validate.validatePoint(p);
  const outputlen = assumeCompression(compressed, p);
  try {
    memory.PUBLIC_KEY_INPUT.set(p);
    wasm.pointCompress(p.length, outputlen);
    return memory.PUBLIC_KEY_INPUT.slice(0, outputlen);
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function pointFromScalar(
  d: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePrivate(d);
  const outputlen = assumeCompression(compressed);
  try {
    memory.PRIVATE_KEY_INPUT.set(d);
    return wasm.pointFromScalar(outputlen) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function xOnlyPointFromScalar(d: Uint8Array): Uint8Array {
  validate.validatePrivate(d);
  try {
    memory.PRIVATE_KEY_INPUT.set(d);
    wasm.xOnlyPointFromScalar();
    return memory.X_ONLY_PUBLIC_KEY_INPUT.slice(
      0,
      validate.X_ONLY_PUBLIC_KEY_SIZE
    );
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
    memory.X_ONLY_PUBLIC_KEY_INPUT.fill(0);
  }
}

export function xOnlyPointFromPoint(p: Uint8Array): Uint8Array {
  validate.validatePoint(p);
  try {
    memory.PUBLIC_KEY_INPUT.set(p);
    wasm.xOnlyPointFromPoint(p.length);
    return memory.X_ONLY_PUBLIC_KEY_INPUT.slice(
      0,
      validate.X_ONLY_PUBLIC_KEY_SIZE
    );
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
    memory.X_ONLY_PUBLIC_KEY_INPUT.fill(0);
  }
}

export function pointMultiply(
  p: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(p);
  validate.validateTweak(tweak);
  const outputlen = assumeCompression(compressed, p);
  try {
    memory.PUBLIC_KEY_INPUT.set(p);
    memory.TWEAK_INPUT.set(tweak);
    return wasm.pointMultiply(p.length, outputlen) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export function privateAdd(
  d: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  validate.validatePrivate(d);
  validate.validateTweak(tweak);
  try {
    memory.PRIVATE_KEY_INPUT.set(d);
    memory.TWEAK_INPUT.set(tweak);
    return wasm.privateAdd() === 1
      ? memory.PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
      : null;
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export function privateSub(
  d: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  validate.validatePrivate(d);
  validate.validateTweak(tweak);

  // We can not pass zero tweak to WASM, because WASM use `secp256k1_ec_seckey_negate` for tweak negate.
  // (zero is not valid seckey)
  if (validate.isZero(tweak)) {
    return new Uint8Array(d);
  }

  try {
    memory.PRIVATE_KEY_INPUT.set(d);
    memory.TWEAK_INPUT.set(tweak);
    return wasm.privateSub() === 1
      ? memory.PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
      : null;
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export function privateNegate(d: Uint8Array): Uint8Array {
  validate.validatePrivate(d);

  try {
    memory.PRIVATE_KEY_INPUT.set(d);
    wasm.privateNegate();
    return memory.PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE);
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
  }
}

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}
export function xOnlyPointAddTweak(
  p: Uint8Array,
  tweak: Uint8Array
): XOnlyPointAddTweakResult | null {
  validate.validateXOnlyPoint(p);
  validate.validateTweak(tweak);
  try {
    memory.X_ONLY_PUBLIC_KEY_INPUT.set(p);
    memory.TWEAK_INPUT.set(tweak);
    const parity = wasm.xOnlyPointAddTweak();
    return parity !== -1
      ? {
          parity,
          xOnlyPubkey: memory.X_ONLY_PUBLIC_KEY_INPUT.slice(
            0,
            validate.X_ONLY_PUBLIC_KEY_SIZE
          ),
        }
      : null;
  } finally {
    memory.X_ONLY_PUBLIC_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export type TweakParity = 1 | 0;
export function xOnlyPointAddTweakCheck(
  point: Uint8Array,
  tweak: Uint8Array,
  resultToCheck: Uint8Array,
  tweakParity?: TweakParity
): boolean {
  validate.validateXOnlyPoint(point);
  validate.validateXOnlyPoint(resultToCheck);
  validate.validateTweak(tweak);
  const hasParity = tweakParity !== undefined;
  if (hasParity) validate.validateParity(tweakParity);
  try {
    memory.X_ONLY_PUBLIC_KEY_INPUT.set(point);
    memory.X_ONLY_PUBLIC_KEY_INPUT2.set(resultToCheck);
    memory.TWEAK_INPUT.set(tweak);
    if (hasParity) {
      return wasm.xOnlyPointAddTweakCheck(tweakParity) === 1;
    } else {
      wasm.xOnlyPointAddTweak();
      const newKey = memory.X_ONLY_PUBLIC_KEY_INPUT.slice(
        0,
        validate.X_ONLY_PUBLIC_KEY_SIZE
      );
      return indexedDB.cmp(newKey, resultToCheck) === 0;
    }
  } finally {
    memory.X_ONLY_PUBLIC_KEY_INPUT.fill(0);
    memory.X_ONLY_PUBLIC_KEY_INPUT2.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export function sign(h: Uint8Array, d: Uint8Array, e?: Uint8Array): Uint8Array {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);
  try {
    memory.HASH_INPUT.set(h);
    memory.PRIVATE_KEY_INPUT.set(d);
    if (e !== undefined) memory.EXTRA_DATA_INPUT.set(e);
    wasm.sign(e === undefined ? 0 : 1);
    return memory.SIGNATURE_INPUT.slice(0, validate.SIGNATURE_SIZE);
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.PRIVATE_KEY_INPUT.fill(0);
    if (e !== undefined) memory.EXTRA_DATA_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
  }
}

export interface RecoverableSignature {
  signature: Uint8Array;
  recoveryId: RecoveryIdType;
}
export function signRecoverable(
  h: Uint8Array,
  d: Uint8Array,
  e?: Uint8Array
): RecoverableSignature {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);
  try {
    memory.HASH_INPUT.set(h);
    memory.PRIVATE_KEY_INPUT.set(d);
    if (e !== undefined) memory.EXTRA_DATA_INPUT.set(e);
    const recoveryId: RecoveryIdType = wasm.signRecoverable(
      e === undefined ? 0 : 1
    );
    const signature: Uint8Array = memory.SIGNATURE_INPUT.slice(
      0,
      validate.SIGNATURE_SIZE
    );
    return {
      signature,
      recoveryId,
    };
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.PRIVATE_KEY_INPUT.fill(0);
    if (e !== undefined) memory.EXTRA_DATA_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
  }
}

export function signSchnorr(
  h: Uint8Array,
  d: Uint8Array,
  e?: Uint8Array
): Uint8Array {
  validate.validateHash(h);
  validate.validatePrivate(d);
  validate.validateExtraData(e);
  try {
    memory.HASH_INPUT.set(h);
    memory.PRIVATE_KEY_INPUT.set(d);
    if (e !== undefined) memory.EXTRA_DATA_INPUT.set(e);
    wasm.signSchnorr(e === undefined ? 0 : 1);
    return memory.SIGNATURE_INPUT.slice(0, validate.SIGNATURE_SIZE);
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.PRIVATE_KEY_INPUT.fill(0);
    if (e !== undefined) memory.EXTRA_DATA_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
  }
}

export function verify(
  h: Uint8Array,
  Q: Uint8Array,
  signature: Uint8Array,
  strict = false
): boolean {
  validate.validateHash(h);
  validate.validatePoint(Q);
  validate.validateSignature(signature);
  try {
    memory.HASH_INPUT.set(h);
    memory.PUBLIC_KEY_INPUT.set(Q);
    memory.SIGNATURE_INPUT.set(signature);
    return wasm.verify(Q.length, strict === true ? 1 : 0) === 1 ? true : false;
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.PUBLIC_KEY_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
  }
}

export type RecoveryIdType = 0 | 1 | 2 | 3;
export function recover(
  h: Uint8Array,
  signature: Uint8Array,
  recoveryId: RecoveryIdType,
  compressed = false
): Uint8Array | null {
  validate.validateHash(h);
  validate.validateSignature(signature);
  validate.validateSignatureNonzeroRS(signature);
  if (recoveryId & 2) {
    validate.validateSigrPMinusN(signature);
  }
  validate.validateSignatureCustom((): boolean =>
    isXOnlyPoint(signature.subarray(0, 32))
  );

  const outputlen = assumeCompression(compressed);
  try {
    memory.HASH_INPUT.set(h);
    memory.SIGNATURE_INPUT.set(signature);

    return wasm.recover(outputlen, recoveryId) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function verifySchnorr(
  h: Uint8Array,
  Q: Uint8Array,
  signature: Uint8Array
): boolean {
  validate.validateHash(h);
  validate.validateXOnlyPoint(Q);
  validate.validateSignature(signature);
  try {
    memory.HASH_INPUT.set(h);
    memory.X_ONLY_PUBLIC_KEY_INPUT.set(Q);
    memory.SIGNATURE_INPUT.set(signature);
    return wasm.verifySchnorr() === 1 ? true : false;
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.X_ONLY_PUBLIC_KEY_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
  }
}
