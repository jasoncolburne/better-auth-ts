import { IDigester } from '../../src/interfaces'
import { TextEncoder } from 'util'
import { Blake3 } from './blake3'
import { Base64 } from '../../src/utils/base64'

export class Digester implements IDigester {
  async sum(message: string): Promise<string> {
    const encoder = new TextEncoder()
    const bytes = encoder.encode(message)
    const digest = await Blake3.sum256(bytes)
    const padded = new Uint8Array([0, ...digest])
    const base64 = Base64.encode(padded)

    return `E${base64.substring(1)}`
  }
}
