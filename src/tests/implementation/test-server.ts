import * as mod from '../../index'
import * as cryptoImpl from './crypto/index.js'
import * as encodingImpl from './encoding/index.js'
import * as storageImpl from './storage/server.js'

let _server: mod.BetterAuthServer | null = null
let _serverInit: Promise<mod.BetterAuthServer> | null = null

async function ensureServer(): Promise<mod.BetterAuthServer> {
  if (_server) return _server
  if (_serverInit) return _serverInit

  _serverInit = (async () => {
    const BetterAuthServer = mod.BetterAuthServer

    const crypto = {
      hasher: new cryptoImpl.Hasher(),
      keyPair: { access: new cryptoImpl.Secp256r1(), response: new cryptoImpl.Secp256r1() },
      noncer: new cryptoImpl.Noncer(),
      verifier: new cryptoImpl.Secp256r1Verifier(),
    }
    const encoding = {
      identityVerifier: new encodingImpl.IdentityVerifier(),
      timestamper: new encodingImpl.Rfc3339Nano(),
      tokenEncoder: new encodingImpl.TokenEncoder(),
    }
    const expiry = { accessInMinutes: 15, refreshInHours: 12 }
    const store = {
      access: { keyHash: new storageImpl.ServerTimeLockStore(60 * 60 * 12) },
      authentication: {
        key: new storageImpl.ServerAuthenticationKeyStore(),
        nonce: new storageImpl.ServerAuthenticationNonceStore(60),
      },
      recovery: { hash: new storageImpl.ServerRecoveryHashStore() },
    }

    await Promise.all([crypto.keyPair.access.generate(), crypto.keyPair.response.generate()])
    const server = new BetterAuthServer({ crypto, encoding, expiry, store })

      ; (server as any).accessVerifier = new mod.AccessVerifier({
        crypto: { publicKey: { access: crypto.keyPair.access }, verifier: crypto.verifier },
        encoding: { tokenEncoder: encoding.tokenEncoder, timestamper: encoding.timestamper },
        store: { access: { nonce: store.access.keyHash } },
      })
    return server
  })()

  return _serverInit
}

async function handleAccessRequest(server: any, path: string, text: string): Promise<string> {
  const verifier = server.accessVerifier as mod.AccessVerifier
  const [identity, payload] = await verifier.verify(text)
  const body = JSON.parse(text)

  // /bad/nonce is a special test route that simulates a bad nonce scenario
  const nonce = path === '/bad/nonce' ? 'bad_nonce' : body?.payload?.access?.nonce ?? ''
  const requestPayload = body?.payload?.request ?? {}

  // For testing, we just echo back some data based on the path
  const responseData =
    path === '/foo/bar'
      ? { wasFoo: requestPayload.foo, wasBar: requestPayload.bar }
      : { ok: true }

  const responseKeyHash = await server['responseKeyHash']?.()
  const serverResponse = new mod.ServerResponse(responseData, responseKeyHash, nonce)
  await serverResponse.sign(server['args'].crypto.keyPair.response)
  return serverResponse.serialize()
}

export default {
  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname
    const server = await ensureServer()
    const text = await request.text()

    const routes: Record<string, (t: string) => Promise<string>> = {
      '/account/create': (t) => server.createAccount(t),
      '/authenticate/start': (t) => server.startAuthentication(t),
      '/authenticate/finish': (t) => server.finishAuthentication(t, {} as {}),
      '/rotate/access': (t) => server.refreshAccessToken(t),
      '/rotate/authentication': (t) => server.rotateAuthenticationKey(t),
      '/rotate/link': (t) => server.linkDevice(t),
      '/rotate/unlink': (t) => server.unlinkDevice(t),
      '/rotate/recover': (t) => server.recoverAccount(t),
      '/key/response': (t) => server.getResponsePublicKey(),
    }

    try {
      const reply =
        path in routes
          ? await routes[path](text)
          : (server as any).accessVerifier
            ? await handleAccessRequest(server, path, text)
            : 'Not Implemented'

      return new Response(reply, { status: 200 })
    } catch (e: any) {
      return new Response(`Internal Server Error: ${e.message}`, { status: 500 })
    }
  },
}
