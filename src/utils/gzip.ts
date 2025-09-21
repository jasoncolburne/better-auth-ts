import Pako from 'pako'
import { setTimeout } from 'timers/promises'

export class Gzip {
  static async deflate(bytes: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      void setTimeout(0, () => {
        try {
          const result = Pako.deflate(bytes)
          resolve(result)
        } catch (error) {
          reject(error)
        }
      })
    })
  }

  static async inflate(bytes: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      void setTimeout(0, () => {
        try {
          const result = Pako.inflate(bytes)
          resolve(result)
        } catch (error) {
          reject(error)
        }
      })
    })
  }
}
