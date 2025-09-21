import { ISigningKey, IVerifier } from '../../interfaces'
import { webcrypto } from 'crypto'
import { TextEncoder } from 'util'
import { Base64 } from '../../utils/base64'

export class Secp256r1Verifier implements IVerifier {
  async verify(message: string, signature: string, publicKey: string): Promise<boolean> {
    const params: webcrypto.EcKeyImportParams = {
      name: 'ECDSA',
      namedCurve: 'P-256',
    }

    const publicKeyBytes = Base64.decode(publicKey).subarray(3)
    const publicCryptoKey = await webcrypto.subtle.importKey('raw', publicKeyBytes, params, true, [
      'verify',
    ])

    const signatureBytes = Base64.decode(signature).subarray(2)

    const encoder = new TextEncoder()
    const messageBytes = encoder.encode(message)

    const verifyParams: webcrypto.EcdsaParams = {
      name: 'ECDSA',
      hash: 'SHA-256',
    }

    return await webcrypto.subtle.verify(
      verifyParams,
      publicCryptoKey,
      signatureBytes,
      messageBytes
    )
  }
}

function isCryptoKeyPair(
  key: webcrypto.CryptoKey | webcrypto.CryptoKeyPair
): key is webcrypto.CryptoKeyPair {
  return 'privateKey' in key && 'publicKey' in key
}

export class Secp256r1 implements ISigningKey {
  keyPair?: webcrypto.CryptoKeyPair
  private readonly _verifier: Secp256r1Verifier

  constructor() {
    this._verifier = new Secp256r1Verifier()
  }

  async generate() {
    const params: webcrypto.EcKeyGenParams = {
      name: 'ECDSA',
      namedCurve: 'P-256',
    }

    const keyPair = await webcrypto.subtle.generateKey(params, true, ['sign', 'verify'])

    if (!isCryptoKeyPair(keyPair)) {
      throw 'unexpected key generated'
    }

    this.keyPair = keyPair
  }

  async sign(message: string): Promise<string> {
    const params: webcrypto.EcdsaParams = {
      name: 'ECDSA',
      hash: 'SHA-256',
    }

    const encoder = new TextEncoder()
    const bytes = encoder.encode(message)

    const signature = await webcrypto.subtle.sign(params, this.keyPair!.privateKey, bytes)

    // todo: check encoding

    const signatureBytes = new Uint8Array(signature)
    const padded = new Uint8Array([0, 0, ...signatureBytes])
    const base64 = Base64.encode(padded)

    return `0I${base64.substring(2)}`
  }

  async public(): Promise<string> {
    if (typeof this.keyPair === 'undefined') {
      throw 'keypair not generated'
    }

    const bytes = await webcrypto.subtle.exportKey('raw', this.keyPair!.publicKey)
    const publicKeyBytes = new Uint8Array(bytes)
    const padded = new Uint8Array([0, 0, 0, ...publicKeyBytes])
    const base64 = Base64.encode(padded)

    return `1AAI${base64.substring(4)}`
  }

  verifier(): IVerifier {
    return this._verifier
  }

  async verify(message: string, signature: string): Promise<boolean> {
    return await this._verifier.verify(message, signature, await this.public())
  }
}
