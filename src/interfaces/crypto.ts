export interface IVerificationKey {
  public(): string
  verifier(): IVerifier
  verify(message: string, signature: string): boolean
}

export interface ISigningKey extends IVerificationKey {
  sign(message: string): string
}

export interface IVerifier {
  verify(message: string, signature: string, publicKey: string): boolean
}

export interface IDigester {
  sum(message: string): string
}

export interface ISalter {
  generate128(): string
}

export interface IKeyDeriver {
  derive(passphrase: string, salt: string, parameters: string): ISigningKey
}
