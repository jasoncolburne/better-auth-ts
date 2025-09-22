import { ISigningKey, IVerifier } from '../interfaces'

interface Signable {
  composePayload(): string
}

interface Serializable {
  serialize(): Promise<string>
}

export abstract class SerializableMessage implements Serializable {
  abstract serialize(): Promise<string>
}

export abstract class SignableMessage extends SerializableMessage implements Signable {
  signature?: string

  abstract composePayload(): string

  async serialize(): Promise<string> {
    if (this.signature === undefined) {
      throw 'null signature'
    }

    return `{"payload":${this.composePayload()},"signature":"${this.signature}"}`
  }

  async sign(signer: ISigningKey): Promise<void> {
    this.signature = await signer.sign(this.composePayload())
  }

  async verify(verifier: IVerifier, publicKey: string): Promise<boolean> {
    if (this.signature === undefined) {
      throw 'null signature'
    }

    return await verifier.verify(this.composePayload(), this.signature, publicKey)
  }
}
