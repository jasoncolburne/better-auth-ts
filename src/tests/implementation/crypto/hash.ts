import { IHasher } from '../../../interfaces/index.js'
import { Base64 } from '../encoding/base64.js'

export class Hasher implements IHasher {
  async sum(message: string): Promise<string> {
    const encoder = new TextEncoder()
    const bytes = encoder.encode(message)
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes)
    const hash = new Uint8Array(hashBuffer)
    const padded = new Uint8Array([0, ...hash])
    const base64 = Base64.encode(padded)

    return `E${base64.substring(1)}`
  }
}
