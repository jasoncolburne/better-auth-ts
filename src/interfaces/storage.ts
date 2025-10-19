import { ISigningKey, IVerificationKey } from './crypto.js'

// client

export interface IClientValueStore {
  store(value: string): Promise<void>

  // throw an exception if:
  // - nothing has been stored
  get(): Promise<string>
}

export interface IClientRotatingKeyStore {
  // returns: [identity, publicKey, rotationHash]
  initialize(extraData?: string): Promise<[string, string, string]>

  // returns: [key, rotationHash]
  //
  // this should return the _next_ signing key and a hash of the subsequent key
  // if no subsequent key exists yet, it should first be generated
  //
  // this facilitates a failed network request during a rotation operation
  next(): Promise<[ISigningKey, string]>

  // throw an exception if:
  // - next() has not been called since the last call to initialize() or rotate()
  //
  // this is the commit operation of next()
  //
  // returns: [publicKey, rotationHash]
  rotate(): Promise<void>

  // returns: effectively, a handle to a signing key
  signer(): Promise<ISigningKey>
}

export interface IVerificationKeyStore {
  get(identity: string): Promise<IVerificationKey>
}

// server

export interface IServerAuthenticationNonceStore {
  lifetimeInSeconds: number

  // probably want to implement exponential backoff delay on generation, per identity
  //
  // returns: nonce
  generate(identity: string): Promise<string>

  // throw an exception if:
  // - nonce is not in the store
  //
  // returns: identity
  validate(nonce: string): Promise<string>
}

export interface IServerAuthenticationKeyStore {
  // throw exceptions for:
  // - identity exists bool set and identity is not found in data store
  // - identity exists bool unset and identity is found in data store
  // - identity and device combination exists
  register(
    identity: string,
    device: string,
    publicKey: string,
    rotationHash: string,
    existingIdentity: boolean
  ): Promise<void>

  // throw exceptions for:
  // - identity and device combination does not exist
  // - previous next hash doesn't match current hash
  rotate(identity: string, device: string, publicKey: string, rotationHash: string): Promise<void>

  // returns: encoded key
  public(identity: string, device: string): Promise<string>

  // revokes access for one device
  revokeDevice(identity: string, device: string): Promise<void>

  // revokes access for all devices
  revokeDevices(identity: string): Promise<void>

  // deletes all devices and the record of identity
  deleteIdentity(identity: string): Promise<void>
}

export interface IServerRecoveryHashStore {
  register(identity: string, keyHash: string): Promise<void>

  // throw exceptions if:
  // - not found
  // - hash does not match
  rotate(identity: string, oldHash: string, newHash: string): Promise<void>

  // this is for forcefully changing the hash if the user loses access to the original
  // it should throw an exception if the identity is not found
  change(identity: string, keyHash: string): Promise<void>
}

export interface IServerTimeLockStore {
  lifetimeInSeconds: number

  // throw an exception if:
  // - value is still alive in the store
  reserve(value: string): Promise<void>
}
