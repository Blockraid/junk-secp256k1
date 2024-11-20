import { Secp256k1WASM } from "./types.js";
import {
  PRIVATE_KEY_SIZE,
  PUBLIC_KEY_UNCOMPRESSED_SIZE,
  X_ONLY_PUBLIC_KEY_SIZE,
  TWEAK_SIZE,
  SIGNATURE_SIZE,
  HASH_SIZE,
  EXTRA_DATA_SIZE,
} from "./validate.js";

const WASM_MEMORY_PRIVATE_KEY_OFFSET = 0;
const WASM_MEMORY_PUBLIC_KEY_OFFSET = WASM_MEMORY_PRIVATE_KEY_OFFSET + PRIVATE_KEY_SIZE;
const WASM_MEMORY_PUBLIC_KEY2_OFFSET = WASM_MEMORY_PUBLIC_KEY_OFFSET + PUBLIC_KEY_UNCOMPRESSED_SIZE;
const WASM_MEMORY_X_ONLY_PUBLIC_KEY_OFFSET = WASM_MEMORY_PUBLIC_KEY2_OFFSET + PUBLIC_KEY_UNCOMPRESSED_SIZE;
const WASM_MEMORY_X_ONLY_PUBLIC_KEY2_OFFSET = WASM_MEMORY_X_ONLY_PUBLIC_KEY_OFFSET + X_ONLY_PUBLIC_KEY_SIZE;
const WASM_MEMORY_TWEAK_OFFSET = WASM_MEMORY_X_ONLY_PUBLIC_KEY2_OFFSET + X_ONLY_PUBLIC_KEY_SIZE;
const WASM_MEMORY_HASH_OFFSET = WASM_MEMORY_TWEAK_OFFSET + TWEAK_SIZE;
const WASM_MEMORY_SIGNATURE_OFFSET = WASM_MEMORY_HASH_OFFSET + HASH_SIZE;
const WASM_MEMORY_EXTRA_DATA_OFFSET = WASM_MEMORY_SIGNATURE_OFFSET + SIGNATURE_SIZE;
const WASM_MEMORY_LEN = WASM_MEMORY_EXTRA_DATA_OFFSET + EXTRA_DATA_SIZE;

export default class Memory {
  private memory: WebAssembly.Memory;
  private view: DataView;
  private u8: Uint8Array;

  constructor(wasm: Secp256k1WASM) {
    this.memory = wasm.memory;
    this.view = new DataView(this.memory.buffer);
    this.u8 = new Uint8Array(this.memory.buffer);
  }

  get PRIVATE_KEY_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_PRIVATE_KEY_OFFSET,
      PRIVATE_KEY_SIZE
    );
  }

  get PUBLIC_KEY_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_PUBLIC_KEY_OFFSET,
      PUBLIC_KEY_UNCOMPRESSED_SIZE
    );
  }

  get PUBLIC_KEY_INPUT2(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_PUBLIC_KEY2_OFFSET,
      PUBLIC_KEY_UNCOMPRESSED_SIZE
    );
  }

  get X_ONLY_PUBLIC_KEY_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_X_ONLY_PUBLIC_KEY_OFFSET,
      X_ONLY_PUBLIC_KEY_SIZE
    );
  }

  get X_ONLY_PUBLIC_KEY_INPUT2(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_X_ONLY_PUBLIC_KEY2_OFFSET,
      X_ONLY_PUBLIC_KEY_SIZE
    );
  }

  get TWEAK_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_TWEAK_OFFSET,
      TWEAK_SIZE
    );
  }

  get HASH_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_HASH_OFFSET,
      HASH_SIZE
    );
  }

  get SIGNATURE_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_SIGNATURE_OFFSET,
      SIGNATURE_SIZE
    );
  }

  get EXTRA_DATA_INPUT(): Uint8Array {
    return new Uint8Array(
      this.memory.buffer,
      WASM_MEMORY_EXTRA_DATA_OFFSET,
      EXTRA_DATA_SIZE
    );
  }
}
