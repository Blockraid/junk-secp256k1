export interface Secp256k1WASM {
  memory: WebAssembly.Memory;
  initializeContext(): void;
  isPoint(inputLen: number): number;
  pointAdd(inputLen1: number, inputLen2: number, outputLen: number): number;
  pointAddScalar(inputLen: number, outputLen: number): number;
  pointCompress(inputLen: number, outputLen: number): void;
  pointFromScalar(outputLen: number): number;
  xOnlyPointFromScalar(): void;
  xOnlyPointFromPoint(inputLen: number): void;
  pointMultiply(inputLen: number, outputLen: number): number;
  privateAdd(): number;
  privateSub(): number;
  privateNegate(): void;
  xOnlyPointAddTweak(): number;
  xOnlyPointAddTweakCheck(tweakParity: number): number;
  sign(hasExtraData: number): void;
  signRecoverable(hasExtraData: number): number;
  signSchnorr(hasExtraData: number): void;
  verify(inputLen: number, strict: number): number;
  recover(outputLen: number, recoveryId: number): number;
  verifySchnorr(): number;
}
