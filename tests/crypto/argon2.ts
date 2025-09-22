import { sodium } from './sodium'

export class Argon2 {
  async derive(passphrase: string, salt: Uint8Array, parameters: string): Promise<Uint8Array> {
    return Promise.resolve(
      (() => {
        const [algorithm, version, params] = parameters
          .substring(1, parameters.length - 1)
          .split('$')

        if (algorithm !== 'argon2id') {
          throw 'incorrect algorithm'
        }

        if (version !== 'v=19') {
          throw 'incorrect version'
        }

        const [mString, tString, pString] = params.split(',')

        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const [_m, m] = mString.split('=')
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const [_t, t] = tString.split('=')
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const [_p, p] = pString.split('=')

        if (p !== '1') {
          throw 'incorrect parallelism'
        }

        const opsLimit = parseInt(t)
        const memLimit = parseInt(m) * 1024

        const keyBytes = sodium.crypto_pwhash(
          32,
          passphrase,
          salt,
          opsLimit,
          memLimit,
          sodium.crypto_pwhash_ALG_ARGON2ID13
        )

        return keyBytes
      })()
    )
  }
}
