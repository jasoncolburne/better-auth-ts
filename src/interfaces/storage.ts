export interface IAccessNonceStore {
    reserve(nonce: string): boolean
}

export interface IRefreshNonceStore {
    create(sessionId: string, nextDigest: string): void
    evolve(current: string, nextDigest: string): void
}

export interface IAuthenticationNonceStore {
    generate(accountId: string): string
    validate(nonce: string): string
}

export interface IRegistrationTokenStore {
    generate(): string
    validate(token: string): string
    invalidate(token: string): void
}

export interface IPassphraseRegistrationTokenStore {
    generate(salt: string, parameters: string): string
    validate(token: string): [string, string, string]
    invalidate(token: string): void
}

export interface IAuthenticationKeyStore {
    register(accountId: string, deviceId: string, current: string, nextDigest: string): void
    rotate(accountId: string, deviceId: string, current: string, nextDigest: string): void
    public(accountId: string, deviceId: string): string
}

export interface IPassphraseAuthenticationKeyStore {
    register(accountId: string, publicKeyDigest: string, salt: string, parameters: string): void
    getDerivationMaterials(accountId: string): [string, string]
    verifyPublicKeyDigest(accountId: string, publicKeyDigest: string): boolean
}

export interface IRefreshKeyStore {
    create(accountId: string, publicKey: string): string
    get(sessionId: string): [string, string]
}