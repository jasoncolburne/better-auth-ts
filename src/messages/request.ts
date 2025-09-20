import { ISigningKey, IVerifier } from '../interfaces/crypto'

interface Signable {
  composePayload(): string
}

interface Serializable {
  serialize(): string
}

export abstract class SerializableMessage implements Serializable {
  abstract serialize(): string
}

export abstract class SignableMessage extends SerializableMessage implements Signable {
  signature?: string

  abstract composePayload(): string

  serialize(): string {
    if (this.signature === undefined) {
      throw 'null signature'
    }

    return `{"payload":${this.composePayload()},"signature":"${this.signature}"}`
  }

  sign(signer: ISigningKey): void {
    this.signature = signer.sign(this.composePayload())
  }

  verify(verifier: IVerifier, publicKey: string): boolean {
    if (this.signature === undefined) {
      throw 'null signature'
    }

    return verifier.verify(this.composePayload(), this.signature, publicKey)
  }
}
