export function getRandomValues(array: Uint8Array): void {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(array);
  } else if (typeof require !== 'undefined') {
    // Node.js
    const { randomFillSync } = require('crypto');
    randomFillSync(array);
  } else {
    throw new Error('No secure random number generator available');
  }
}

export function randomBytes(size: number): Uint8Array {
  const array = new Uint8Array(size);
  getRandomValues(array);
  return array;
}
