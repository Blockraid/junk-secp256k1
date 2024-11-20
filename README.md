# junk-secp256k1

TypeScript bindings for secp256k1 optimized for Junkcoin.

## Features

- Optimized secp256k1 cryptographic operations
- WebAssembly-based for high performance
- TypeScript support
- Secure random number generation
- Key pair generation and manipulation
- Message signing and verification
- Public key recovery from signatures
- Point addition and scalar multiplication
- Private key tweaking

## Installation

```bash
npm install junk-secp256k1
```

## Usage

```typescript
import * as secp256k1 from 'junk-secp256k1';

// Initialize the library
await secp256k1.initializeSecp256k1();

// Generate public key from private key
const publicKey = secp256k1.pointFromPrivateKey(privateKey, true); // true for compressed

// Sign a message
const signature = secp256k1.sign(messageHash, privateKey);

// Verify a signature
const isValid = secp256k1.verify(messageHash, signature, publicKey);

// Add tweak to private key
const tweakedPrivateKey = secp256k1.privateKeyTweakAdd(privateKey, tweak);

// Add tweak to public key
const tweakedPublicKey = secp256k1.publicKeyTweakAdd(publicKey, tweak);
```

## Security

This library implements cryptographic operations. Please use it with caution and review the code before using it in production.

## License

MIT
