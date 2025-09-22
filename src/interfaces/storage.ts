import { ISigningKey } from './crypto'

export interface IClientValueStore {
  store(value: string): Promise<void>
  get(): Promise<string>
}

export interface IServerAccessNonceStore {
  reserve(accountId: string, nonce: string): Promise<void>
}

export interface IServerAuthenticationNonceStore {
  generate(accountId: string): Promise<string>
  validate(nonce: string): Promise<string>
}

export interface IServerRegistrationTokenStore {
  generate(): Promise<string>
  validate(token: string): Promise<string>
  invalidate(token: string): Promise<void>
}

export interface IClientRotatingKeyStore {
  initialize(): Promise<[string, string]>
  rotate(): Promise<[string, string]>
  signer(): ISigningKey
}

export interface IServerAuthenticationKeyStore {
  register(accountId: string, deviceId: string, current: string, nextDigest: string): Promise<void>
  rotate(accountId: string, deviceId: string, current: string, nextDigest: string): Promise<void>
  public(accountId: string, deviceId: string): string
}
