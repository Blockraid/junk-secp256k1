export class InvalidPrivateKeyError extends Error {
  constructor() {
    super("Invalid private key");
    this.name = "InvalidPrivateKeyError";
  }
}

export class InvalidPublicKeyError extends Error {
  constructor() {
    super("Invalid public key");
    this.name = "InvalidPublicKeyError";
  }
}

export class InvalidSignatureError extends Error {
  constructor() {
    super("Invalid signature");
    this.name = "InvalidSignatureError";
  }
}

export class InvalidHashError extends Error {
  constructor() {
    super("Invalid hash");
    this.name = "InvalidHashError";
  }
}

export class InvalidTweakError extends Error {
  constructor() {
    super("Invalid tweak");
    this.name = "InvalidTweakError";
  }
}

export class InvalidExtraDataError extends Error {
  constructor() {
    super("Invalid extra data");
    this.name = "InvalidExtraDataError";
  }
}

export class InvalidParityError extends Error {
  constructor() {
    super("Invalid parity");
    this.name = "InvalidParityError";
  }
}
