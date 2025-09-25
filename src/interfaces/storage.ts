import { ISigningKey } from './crypto'

// client

export interface IClientValueStore {
  store(value: string): Promise<void>

  // throw an exception if:
  // - nothing has been stored
  get(): Promise<string>
}

export interface IClientRotatingKeyStore {
  // returns: [current public key, next public key hash]
  initialize(): Promise<[string, string]>

  // throw an exception if:
  // - no keys exist
  //
  // returns: [current public key, next public key hash]
  rotate(): Promise<[string, string]>

  // returns: effectively, a handle to a signing key
  signer(): Promise<ISigningKey>
}

// server

export interface IServerAuthenticationNonceStore {
  lifetimeInSeconds: number

  // probably want to implement exponential backoff delay on generation, per account
  //
  // returns: nonce
  generate(identity: string): Promise<string>

  // throw an exception if:
  // - nonce is not in the store
  //
  // returns: account id
  validate(nonce: string): Promise<string>
}

export interface IServerAuthenticationKeyStore {
  // throw an exception for:
  // - account id and device id combination exists
  register(
    identity: string,
    device: string,
    current: string,
    rotationHash: string
  ): Promise<void>

  // throw exceptions for:
  // - account id and device id combination does not exist
  // - previous next hash doesn't match current hash
  rotate(identity: string, device: string, current: string, rotationHash: string): Promise<void>

  // returns: encoded key
  public(identity: string, device: string): Promise<string>
}

export interface IServerRecoveryHashStore {
  register(identity: string, keyHash: string): Promise<void>

  // throw exceptions if:
  // - not found
  // - hash does not match
  validate(identity: string, keyHash: string): Promise<void>
}

export interface IServerTimeLockStore {
  lifetimeInSeconds: number

  // throw an exception if:
  // - value is still alive in the store
  reserve(value: string): Promise<void>
}
