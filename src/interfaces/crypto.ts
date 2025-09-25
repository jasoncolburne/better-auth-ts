export interface IHasher {
  sum(message: string): Promise<string>
}

export interface INoncer {
  // 128 bits of entropy
  generate128(): Promise<string>
}

export interface IVerifier {
  signatureLength: number

  // this is typically just a verification algorithm
  //
  // throw exceptions when verification fails
  verify(message: string, signature: string, publicKey: string): Promise<void>
}

export interface IVerificationKey {
  // fetches the public key
  public(): Promise<string>

  // returns the algorithm verifier
  verifier(): IVerifier

  // verifies using the verifier and public key, this ia a convenience method
  //
  // throw exceptions when verification fails
  verify(message: string, signature: string): Promise<void>
}

export interface ISigningKey extends IVerificationKey {
  // signs with the key it represents (could be backed by an HSM for instance)
  sign(message: string): Promise<string>
}
