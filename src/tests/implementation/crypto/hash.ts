import { IHasher } from '../../../interfaces'
import { TextEncoder } from 'util'
import { Blake3 } from './blake3'
import { Base64 } from '../../../utils/base64'

export class Hasher implements IHasher {
  async sum(message: string): Promise<string> {
    const encoder = new TextEncoder()
    const bytes = encoder.encode(message)
    const hash = await Blake3.sum256(bytes)
    const padded = new Uint8Array([0, ...hash])
    const base64 = Base64.encode(padded)

    return `E${base64.substring(1)}`
  }
}
