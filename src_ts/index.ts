import * as validate from "./validate.js";
import * as validate_error from "./validate_error.js";
import * as rand from "./rand.js";
import Memory from "./memory.js";
import { Secp256k1WASM } from "./types.js";

let wasm = {} as unknown as Secp256k1WASM;
let memory = {} as unknown as Memory;

// Initialize WebAssembly module
export async function initializeSecp256k1(): Promise<void> {
  try {
    const response = await fetch('secp256k1.wasm');
    const wasmBuffer = await response.arrayBuffer();
    const wasmModule = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(wasmModule, {
      "./rand.js": rand,
      "./validate_error.js": validate_error,
    });
    wasm = instance.exports as unknown as Secp256k1WASM;
    memory = new Memory(wasm);
    wasm.initializeContext();
  } catch (error) {
    console.error('Failed to initialize secp256k1:', error);
    throw error;
  }
}

function assumeCompression(compressed?: boolean, p?: Uint8Array): number {
  if (compressed === undefined) {
    return p !== undefined ? p.length : validate.PUBLIC_KEY_COMPRESSED_SIZE;
  }
  return compressed
    ? validate.PUBLIC_KEY_COMPRESSED_SIZE
    : validate.PUBLIC_KEY_UNCOMPRESSED_SIZE;
}

export function isPoint(p: Uint8Array): boolean {
  validate.validatePoint(p);
  try {
    memory.PUBLIC_KEY_INPUT.set(p);
    return wasm.isPoint(p.length) === 1;
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function pointFromPrivateKey(
  privateKey: Uint8Array,
  compressed = true
): Uint8Array | null {
  validate.validatePrivate(privateKey);
  const outputlen = assumeCompression(compressed);
  try {
    memory.PRIVATE_KEY_INPUT.set(privateKey);
    return wasm.pointFromScalar(outputlen) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function sign(
  messageHash: Uint8Array,
  privateKey: Uint8Array,
  extraEntropy?: Uint8Array
): Uint8Array {
  validate.validateHash(messageHash);
  validate.validatePrivate(privateKey);
  validate.validateExtraData(extraEntropy);
  try {
    memory.HASH_INPUT.set(messageHash);
    memory.PRIVATE_KEY_INPUT.set(privateKey);
    if (extraEntropy !== undefined) memory.EXTRA_DATA_INPUT.set(extraEntropy);
    wasm.sign(extraEntropy === undefined ? 0 : 1);
    return memory.SIGNATURE_INPUT.slice(0, validate.SIGNATURE_SIZE);
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.PRIVATE_KEY_INPUT.fill(0);
    if (extraEntropy !== undefined) memory.EXTRA_DATA_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
  }
}

export function verify(
  messageHash: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  strict = true
): boolean {
  validate.validateHash(messageHash);
  validate.validateSignature(signature);
  validate.validatePoint(publicKey);
  try {
    memory.HASH_INPUT.set(messageHash);
    memory.SIGNATURE_INPUT.set(signature);
    memory.PUBLIC_KEY_INPUT.set(publicKey);
    return wasm.verify(publicKey.length, strict ? 1 : 0) === 1;
  } finally {
    memory.HASH_INPUT.fill(0);
    memory.SIGNATURE_INPUT.fill(0);
    memory.PUBLIC_KEY_INPUT.fill(0);
  }
}

export function privateKeyTweakAdd(
  privateKey: Uint8Array,
  tweak: Uint8Array
): Uint8Array | null {
  validate.validatePrivate(privateKey);
  validate.validateTweak(tweak);
  try {
    memory.PRIVATE_KEY_INPUT.set(privateKey);
    memory.TWEAK_INPUT.set(tweak);
    return wasm.privateAdd() === 1
      ? memory.PRIVATE_KEY_INPUT.slice(0, validate.PRIVATE_KEY_SIZE)
      : null;
  } finally {
    memory.PRIVATE_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export function publicKeyTweakAdd(
  publicKey: Uint8Array,
  tweak: Uint8Array,
  compressed?: boolean
): Uint8Array | null {
  validate.validatePoint(publicKey);
  validate.validateTweak(tweak);
  const outputlen = assumeCompression(compressed, publicKey);
  try {
    memory.PUBLIC_KEY_INPUT.set(publicKey);
    memory.TWEAK_INPUT.set(tweak);
    return wasm.pointAddScalar(publicKey.length, outputlen) === 1
      ? memory.PUBLIC_KEY_INPUT.slice(0, outputlen)
      : null;
  } finally {
    memory.PUBLIC_KEY_INPUT.fill(0);
    memory.TWEAK_INPUT.fill(0);
  }
}

export { validate_error };
