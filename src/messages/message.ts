import { ISigningKey, IVerifier } from '../interfaces/index.js'
import { InvalidMessageError } from '../errors.js'

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
  payload?: object
  signature?: string

  composePayload(): string {
    if (typeof this.payload === 'undefined') {
      throw new InvalidMessageError('payload', 'payload is undefined')
    }

    return JSON.stringify(this.payload)
  }

  async serialize(): Promise<string> {
    if (this.signature === undefined) {
      throw new InvalidMessageError('signature', 'signature is null or undefined')
    }

    return `{"payload":${this.composePayload()},"signature":"${this.signature}"}`
  }

  async sign(signer: ISigningKey): Promise<void> {
    this.signature = await signer.sign(this.composePayload())
  }

  async verify(verifier: IVerifier, publicKey: string): Promise<void> {
    if (this.signature === undefined) {
      throw new InvalidMessageError('signature', 'signature is null or undefined')
    }

    await verifier.verify(this.composePayload(), this.signature, publicKey)
  }
}
