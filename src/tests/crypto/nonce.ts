import { INoncer } from '../../interfaces'
import { Base64 } from '../../utils/base64'
import { getEntropy } from './entropy'

export class Noncer implements INoncer {
  async generate128(): Promise<string> {
    const entropy = await getEntropy(16)

    const padded = new Uint8Array([0, 0, ...entropy])
    const base64 = Base64.encode(padded)

    return `0A${base64.substring(2)}`
  }
}
