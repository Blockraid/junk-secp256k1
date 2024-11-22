import { Secp256k1WASM } from "./types.js";
import * as validate from "./validate.js";

export default class Memory {
  WASM_BUFFER: Uint8Array;
  PRIVATE_KEY_INPUT: Uint8Array;
  PUBLIC_KEY_INPUT: Uint8Array;
  PUBLIC_KEY_INPUT2: Uint8Array;
  X_ONLY_PUBLIC_KEY_INPUT: Uint8Array;
  X_ONLY_PUBLIC_KEY_INPUT2: Uint8Array;
  TWEAK_INPUT: Uint8Array;
  HASH_INPUT: Uint8Array;
  EXTRA_DATA_INPUT: Uint8Array;
  SIGNATURE_INPUT: Uint8Array;

  constructor(wasm: Secp256k1WASM) {
    this.WASM_BUFFER = new Uint8Array(wasm.memory.buffer);
    const WASM_PRIVATE_KEY_PTR = wasm.PRIVATE_INPUT.value;
    const WASM_PUBLIC_KEY_INPUT_PTR = wasm.PUBLIC_KEY_INPUT.value;
    const WASM_PUBLIC_KEY_INPUT_PTR2 = wasm.PUBLIC_KEY_INPUT2.value;
    const WASM_X_ONLY_PUBLIC_KEY_INPUT_PTR = wasm.X_ONLY_PUBLIC_KEY_INPUT.value;
    const WASM_X_ONLY_PUBLIC_KEY_INPUT2_PTR =
      wasm.X_ONLY_PUBLIC_KEY_INPUT2.value;
    const WASM_TWEAK_INPUT_PTR = wasm.TWEAK_INPUT.value;
    const WASM_HASH_INPUT_PTR = wasm.HASH_INPUT.value;
    const WASM_EXTRA_DATA_INPUT_PTR = wasm.EXTRA_DATA_INPUT.value;
    const WASM_SIGNATURE_INPUT_PTR = wasm.SIGNATURE_INPUT.value;
    this.PRIVATE_KEY_INPUT = this.WASM_BUFFER.subarray(
      WASM_PRIVATE_KEY_PTR,
      WASM_PRIVATE_KEY_PTR + validate.PRIVATE_KEY_SIZE
    );
    this.PUBLIC_KEY_INPUT = this.WASM_BUFFER.subarray(
      WASM_PUBLIC_KEY_INPUT_PTR,
      WASM_PUBLIC_KEY_INPUT_PTR + validate.PUBLIC_KEY_UNCOMPRESSED_SIZE
    );
    this.PUBLIC_KEY_INPUT2 = this.WASM_BUFFER.subarray(
      WASM_PUBLIC_KEY_INPUT_PTR2,
      WASM_PUBLIC_KEY_INPUT_PTR2 + validate.PUBLIC_KEY_UNCOMPRESSED_SIZE
    );
    this.X_ONLY_PUBLIC_KEY_INPUT = this.WASM_BUFFER.subarray(
      WASM_X_ONLY_PUBLIC_KEY_INPUT_PTR,
      WASM_X_ONLY_PUBLIC_KEY_INPUT_PTR + validate.X_ONLY_PUBLIC_KEY_SIZE
    );
    this.X_ONLY_PUBLIC_KEY_INPUT2 = this.WASM_BUFFER.subarray(
      WASM_X_ONLY_PUBLIC_KEY_INPUT2_PTR,
      WASM_X_ONLY_PUBLIC_KEY_INPUT2_PTR + validate.X_ONLY_PUBLIC_KEY_SIZE
    );
    this.TWEAK_INPUT = this.WASM_BUFFER.subarray(
      WASM_TWEAK_INPUT_PTR,
      WASM_TWEAK_INPUT_PTR + validate.TWEAK_SIZE
    );
    this.HASH_INPUT = this.WASM_BUFFER.subarray(
      WASM_HASH_INPUT_PTR,
      WASM_HASH_INPUT_PTR + validate.HASH_SIZE
    );
    this.EXTRA_DATA_INPUT = this.WASM_BUFFER.subarray(
      WASM_EXTRA_DATA_INPUT_PTR,
      WASM_EXTRA_DATA_INPUT_PTR + validate.EXTRA_DATA_SIZE
    );
    this.SIGNATURE_INPUT = this.WASM_BUFFER.subarray(
      WASM_SIGNATURE_INPUT_PTR,
      WASM_SIGNATURE_INPUT_PTR + validate.SIGNATURE_SIZE
    );
  }
}
