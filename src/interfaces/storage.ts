import { ISigningKey } from './crypto'

export interface IClientValueStore {
  store(accountId: string): Promise<void>
  get(): Promise<string>
}

export interface IServerAccessNonceStore {
  reserve(accountId: string, nonce: string): Promise<void>
}

export interface IServerRefreshNonceStore {
  create(sessionId: string, nextDigest: string): Promise<void>
  evolve(sessionId: string, current: string, nextDigest: string): Promise<void>
}

export interface IClientRefreshNonceStore {
  initialize(): Promise<string>
  evolve(): Promise<[string, string]>
}

export interface IServerAuthenticationNonceStore {
  generate(accountId: string): Promise<string>
  validate(nonce: string): Promise<string>
}

export interface IServerAuthenticationRegistrationTokenStore {
  generate(): Promise<string>
  validate(token: string): Promise<string>
  invalidate(token: string): Promise<void>
}

export interface IServerPassphraseRegistrationTokenStore {
  generate(salt: string, parameters: string): Promise<string>
  validate(token: string): Promise<[string, string, string]>
  invalidate(token: string): Promise<void>
}

export interface IClientRotatingKeyStore {
  initialize(): Promise<[string, string]>
  rotate(): Promise<[string, string]>
  signer(): ISigningKey
}

export interface IClientSingleKeyStore {
  generate(): Promise<string>
  signer(): ISigningKey
}

export interface IServerAuthenticationKeyStore {
  register(accountId: string, deviceId: string, current: string, nextDigest: string): Promise<void>
  rotate(accountId: string, deviceId: string, current: string, nextDigest: string): Promise<void>
  public(accountId: string, deviceId: string): string
}

export interface IServerPassphraseAuthenticationKeyStore {
  register(
    accountId: string,
    publicKeyDigest: string,
    salt: string,
    parameters: string
  ): Promise<void>
  getDerivationMaterials(accountId: string): Promise<[string, string]>
  verifyPublicKeyDigest(accountId: string, publicKeyDigest: string): Promise<boolean>
}

export interface IServerRefreshKeyStore {
  create(accountId: string, publicKey: string): Promise<string>
  get(sessionId: string): Promise<[string, string]>
}
