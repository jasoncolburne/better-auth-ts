import { ISigningKey } from './crypto'

// client

export interface IClientValueStore {
  store(value: string): Promise<void>

  // throw an exception if:
  // - nothing has been stored
  get(): Promise<string>
}

export interface IClientRotatingKeyStore {
  // returns: [current public key, next public key digest]
  initialize(): Promise<[string, string]>

  // throw an exception if:
  // - no keys exist
  //
  // returns: [current public key, next public key digest]
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
  generate(accountId: string): Promise<string>

  // throw an exception if:
  // - nonce is not in the store
  //
  // returns: account id
  validate(nonce: string): Promise<string>
}

export interface IServerCreationTokenStore {
  lifetimeInMinutes: number

  // returns: token
  generate(): Promise<string>

  // throw an exception if:
  // - the token is not in the store
  // - the token is more than `lifetimeInMinutes` minutes old
  //
  // returns: account id
  validate(token: string): Promise<string>

  // throw an exception if:
  // - the token is not in the store
  invalidate(token: string): Promise<void>
}

export interface IServerAuthenticationKeyStore {
  // throw an exception for:
  // - account id and device id combination exists
  register(
    accountId: string,
    deviceId: string,
    current: string,
    rotationDigest: string
  ): Promise<void>

  // throw exceptions for:
  // - account id and device id combination does not exist
  // - previous next digest doesn't match current digest
  rotate(
    accountId: string,
    deviceId: string,
    current: string,
    rotationDigest: string
  ): Promise<void>

  // returns: encoded key
  public(accountId: string, deviceId: string): Promise<string>
}

export interface IServerrecoveryDigestStore {
  register(accountId: string, keyDigest: string): Promise<void>

  // throw exceptions if:
  // - not found
  // - digest does not match
  validate(accountId: string, keyDigest: string): Promise<void>
}

export interface IServerTimeLockStore {
  lifetimeInSeconds: number

  // throw an exception if:
  // - value is still alive in the store
  reserve(value: string): Promise<void>
}
