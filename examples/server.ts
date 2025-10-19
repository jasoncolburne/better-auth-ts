/* eslint-disable no-console */
import http from 'http'
import { AccessVerifier, BetterAuthServer } from '../src/api'
import { ServerResponse } from '../src/messages'
import {
  Hasher,
  IdentityVerifier,
  Noncer,
  Rfc3339Nano,
  Secp256r1,
  Secp256r1Verifier,
  ServerAuthenticationKeyStore,
  ServerAuthenticationNonceStore,
  ServerRecoveryHashStore,
  ServerTimeLockStore,
  TokenEncoder,
  VerificationKeyStore,
} from '../src/tests/implementation'

interface MockTokenAttributes {
  permissionsByRole: Record<string, string[]>
}

interface MockRequestPayload {
  foo: string
  bar: string
}

interface MockResponsePayload {
  wasFoo: string
  wasBar: string
}

class Server {
  private readonly ba: BetterAuthServer
  private readonly av: AccessVerifier
  private readonly serverResponseKey: Secp256r1

  constructor() {
    const accessLifetime = 15 // minutes
    const accessWindow = 30 // seconds
    const refreshLifetime = 12 // hours
    const authenticationChallengeLifetime = 60 // seconds

    const hasher = new Hasher()
    const verifier = new Secp256r1Verifier()
    const noncer = new Noncer()

    const accessKeyHashStore = new ServerTimeLockStore(refreshLifetime * 3600)
    const accessNonceStore = new ServerTimeLockStore(accessWindow)
    const authenticationKeyStore = new ServerAuthenticationKeyStore()
    const authenticationNonceStore = new ServerAuthenticationNonceStore(
      authenticationChallengeLifetime
    )
    const recoveryHashStore = new ServerRecoveryHashStore()

    const identityVerifier = new IdentityVerifier()
    const timestamper = new Rfc3339Nano()
    const tokenEncoder = new TokenEncoder()

    this.serverResponseKey = new Secp256r1()
    const serverAccessKey = new Secp256r1()

    this.ba = new BetterAuthServer({
      crypto: {
        hasher: hasher,
        keyPair: {
          access: serverAccessKey,
          response: this.serverResponseKey,
        },
        noncer: noncer,
        verifier: verifier,
      },
      encoding: {
        identityVerifier: identityVerifier,
        timestamper: timestamper,
        tokenEncoder: tokenEncoder,
      },
      expiry: {
        accessInMinutes: accessLifetime,
        refreshInHours: refreshLifetime,
      },
      store: {
        access: {
          keyHash: accessKeyHashStore,
        },
        authentication: {
          key: authenticationKeyStore,
          nonce: authenticationNonceStore,
        },
        recovery: {
          hash: recoveryHashStore,
        },
      },
    })

    const accessKeyStore = new VerificationKeyStore()
    // We'll add the server access key after initialization
    this.accessKeyStore = accessKeyStore
    this.serverAccessKey = serverAccessKey

    this.av = new AccessVerifier({
      crypto: {
        verifier: verifier,
      },
      encoding: {
        tokenEncoder: tokenEncoder,
        timestamper: timestamper,
      },
      store: {
        access: {
          nonce: accessNonceStore,
          key: accessKeyStore,
        },
      },
    })
  }

  private readonly accessKeyStore: VerificationKeyStore
  private readonly serverAccessKey: Secp256r1

  async initialize(): Promise<void> {
    await this.serverResponseKey.generate()
    await this.serverAccessKey.generate()
    const serverAccessIdentity = await this.serverAccessKey.identity()
    await this.accessKeyStore.add(serverAccessIdentity, this.serverAccessKey)
  }

  private async wrapResponse(
    body: string,
    logic: (message: string) => Promise<string>
  ): Promise<string> {
    try {
      return await logic(body)
    } catch (e) {
      console.error('error:', e)
      return JSON.stringify({ error: 'an error occurred' })
    }
  }

  async create(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.createAccount(message))
  }

  async recover(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.recoverAccount(message))
  }

  async delete(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.deleteAccount(message))
  }

  async link(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.linkDevice(message))
  }

  async unlink(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.unlinkDevice(message))
  }

  async startAuthentication(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.requestSession(message))
  }

  async finishAuthentication(body: string): Promise<string> {
    return this.wrapResponse(body, async message =>
      this.ba.createSession<MockTokenAttributes>(message, {
        permissionsByRole: {
          admin: ['read', 'write'],
        },
      })
    )
  }

  async rotateAuthentication(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.rotateDevice(message))
  }

  async rotateAccess(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.refreshSession(message))
  }

  async changeRecoveryKey(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.ba.changeRecoveryKey(message))
  }

  async responseKey(body: string): Promise<string> {
    return this.wrapResponse(body, async () => this.serverResponseKey.public())
  }

  private async respondToAccessRequest(message: string, badNonce: boolean): Promise<string> {
    const [request, _token, requestNonce] = await this.av.verify<
      MockRequestPayload,
      MockTokenAttributes
    >(message)

    const serverIdentity = await this.serverResponseKey.identity()

    const nonce = badNonce ? '0A0123456789' : requestNonce

    const response = new ServerResponse<MockResponsePayload>(
      {
        wasFoo: request.foo,
        wasBar: request.bar,
      },
      serverIdentity,
      nonce
    )

    await response.sign(this.serverResponseKey)

    return await response.serialize()
  }

  async fooBar(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.respondToAccessRequest(message, false))
  }

  async badNonce(body: string): Promise<string> {
    return this.wrapResponse(body, async message => this.respondToAccessRequest(message, true))
  }
}

async function main(): Promise<void> {
  const server = new Server()
  await server.initialize()

  const httpServer = http.createServer(async (req, res) => {
    if (req.method === 'POST') {
      let body = ''
      req.on('data', chunk => {
        body += chunk.toString()
      })

      req.on('end', async () => {
        try {
          let response = ''

          switch (req.url) {
            case '/account/create':
              response = await server.create(body)
              break
            case '/account/recover':
              response = await server.recover(body)
              break
            case '/account/delete':
              response = await server.delete(body)
              break
            case '/session/request':
              response = await server.startAuthentication(body)
              break
            case '/session/create':
              response = await server.finishAuthentication(body)
              break
            case '/session/refresh':
              response = await server.rotateAccess(body)
              break
            case '/device/rotate':
              response = await server.rotateAuthentication(body)
              break
            case '/device/link':
              response = await server.link(body)
              break
            case '/device/unlink':
              response = await server.unlink(body)
              break
            case '/recovery/change':
              response = await server.changeRecoveryKey(body)
              break
            case '/key/response':
              response = await server.responseKey(body)
              break
            case '/foo/bar':
              response = await server.fooBar(body)
              break
            case '/bad/nonce':
              response = await server.badNonce(body)
              break
            default:
              res.writeHead(404)
              res.end()
              return
          }

          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          })
          res.end(response)
        } catch (error) {
          console.error('Unhandled error in request handler:', error)
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' })
            res.end(JSON.stringify({ error: 'Internal server error' }))
          }
        }
      })
    } else if (req.method === 'OPTIONS') {
      res.writeHead(200, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      })
      res.end()
    } else {
      res.writeHead(405)
      res.end()
    }
  })

  httpServer.listen(8080, '127.0.0.1', () => {
    console.log('Server running on http://127.0.0.1:8080')
  })
}

main().catch(console.error)
