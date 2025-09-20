import { ISigningKey, IVerifier } from '../interfaces/crypto'

interface Signable {
  composePayload(): string
  sign(signer: ISigningKey): void
}

interface Verifiable {
  verify(verifier: IVerifier, publicKey: string): boolean
}

interface Serializable {
  serialize(signer?: ISigningKey): string
}

export abstract class SerializableMessage implements Serializable {
  abstract serialize(signer?: ISigningKey): string
}

export abstract class SignableMessage extends SerializableMessage implements Signable, Verifiable {
  signature?: string

  abstract composePayload(): string

  serialize(): string {
    if (this.signature == null) {
      throw 'null signature'
    }

    return `{"payload":${this.composePayload()},"signature":"${this.signature}"}`
  }

  sign(signer: ISigningKey) {
    this.signature = signer.sign(this.composePayload())
  }

  verify(verifier: IVerifier, publicKey: string): boolean {
    if (this.signature == null) {
      throw 'null signature'
    }

    return verifier.verify(this.composePayload(), this.signature, publicKey)
  }
}
