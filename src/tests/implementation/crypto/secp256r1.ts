import { ISigningKey, IVerifier } from '../../../interfaces/index.js'
import { InvalidMessageError } from '../../../errors.js'
import { webcrypto } from 'crypto'
import { TextEncoder } from 'util'
import { Base64 } from '../encoding/base64.js'

export class Secp256r1Verifier implements IVerifier {
  async verify(message: string, signature: string, publicKey: string): Promise<void> {
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

    if (
      !(await webcrypto.subtle.verify(verifyParams, publicCryptoKey, signatureBytes, messageBytes))
    ) {
      throw new Error('Signature verification failed')
    }
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

  async identity(): Promise<string> {
    return await this.public()
  }

  async generate() {
    const params: webcrypto.EcKeyGenParams = {
      name: 'ECDSA',
      namedCurve: 'P-256',
    }

    const keyPair = await webcrypto.subtle.generateKey(params, true, ['sign', 'verify'])

    if (!isCryptoKeyPair(keyPair)) {
      throw new InvalidMessageError('keyPair', 'unexpected key type generated')
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
    const signatureBytes = new Uint8Array(signature)
    const padded = new Uint8Array([0, 0, ...signatureBytes])
    const base64 = Base64.encode(padded)

    return `0I${base64.substring(2)}`
  }

  async public(): Promise<string> {
    if (typeof this.keyPair === 'undefined') {
      throw new InvalidMessageError('keyPair', 'keypair not generated')
    }

    const raw = await webcrypto.subtle.exportKey('raw', this.keyPair!.publicKey)
    const uncompressed = new Uint8Array(raw)
    const compressed = this.compressPublicKey(uncompressed)

    const padded = new Uint8Array([0, 0, 0, ...compressed])
    const base64 = Base64.encode(padded)

    return `1AAI${base64.substring(4)}`
  }

  verifier(): IVerifier {
    return this._verifier
  }

  async verify(message: string, signature: string): Promise<void> {
    await this._verifier.verify(message, signature, await this.public())
  }

  private compressPublicKey(uncompressedKey: Uint8Array): Uint8Array {
    if (uncompressedKey.length !== 65) {
      throw new InvalidMessageError('publicKey', `invalid length: ${uncompressedKey.length}, expected 65`)
    }

    if (uncompressedKey[0] !== 0x04) {
      throw new InvalidMessageError('publicKey', `invalid byte header: ${uncompressedKey[0]}, expected 0x04`)
    }

    const x = uncompressedKey.slice(1, 33)
    const y = uncompressedKey.slice(33, 65)

    const yParity = y[31] & 1
    const prefix = yParity === 0 ? 0x02 : 0x03

    const compressedKey = new Uint8Array(33)
    compressedKey[0] = prefix
    compressedKey.set(x, 1)

    return compressedKey
  }
}
