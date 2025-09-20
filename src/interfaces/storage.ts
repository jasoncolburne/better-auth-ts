import { ISigningKey } from './crypto'

export interface IClientValueStore {
  store(accountId: string): void
  get(): string
}

export interface IServerAccessNonceStore {
  reserve(nonce: string): boolean
}

export interface IServerRefreshNonceStore {
  create(sessionId: string, nextDigest: string): void
  evolve(current: string, nextDigest: string): void
}

export interface IClientRefreshNonceStore {
  initialize(): string
  evolve(): [string, string]
}

export interface IServerAuthenticationNonceStore {
  generate(accountId: string): string
  validate(nonce: string): string
}

export interface IServerRegistrationTokenStore {
  generate(): string
  validate(token: string): string
  invalidate(token: string): void
}

export interface IServerPassphraseRegistrationTokenStore {
  generate(salt: string, parameters: string): string
  validate(token: string): [string, string, string]
  invalidate(token: string): void
}

export interface IClientRotatingKeyStore {
  initialize(): [string, string]
  rotate(): [string, string]
  signer(): ISigningKey
}

export interface IClientSingleKeyStore {
  generate(): string
  signer(): ISigningKey
}

export interface IServerAuthenticationKeyStore {
  register(accountId: string, deviceId: string, current: string, nextDigest: string): void
  rotate(accountId: string, deviceId: string, current: string, nextDigest: string): void
  public(accountId: string, deviceId: string): string
}

export interface IServerPassphraseAuthenticationKeyStore {
  register(accountId: string, publicKeyDigest: string, salt: string, parameters: string): void
  getDerivationMaterials(accountId: string): [string, string]
  verifyPublicKeyDigest(accountId: string, publicKeyDigest: string): boolean
}

export interface IServerRefreshKeyStore {
  create(accountId: string, publicKey: string): string
  get(sessionId: string): [string, string]
}
