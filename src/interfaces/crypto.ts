export interface IDigester {
  sum(message: string): Promise<string>
}

export interface INoncer {
  generate128(): Promise<string>
}

export interface IVerifier {
  verify(message: string, signature: string, publicKey: string): Promise<boolean>
}

export interface IVerificationKey {
  public(): Promise<string>
  verifier(): IVerifier
  verify(message: string, signature: string): Promise<boolean>
}

export interface ISigningKey extends IVerificationKey {
  sign(message: string): Promise<string>
}
