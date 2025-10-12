# Better Auth - TypeScript Implementation

## Project Context

This is the **reference TypeScript implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation is special because:
- It's the **reference implementation** - other language implementations follow its patterns
- It includes **both client and server** components
- It generates the protocol examples in the main spec using CESR encoding
- It serves as the canonical source for protocol behavior

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Other Implementations:**
- Full (Client + Server): [Python](https://github.com/jasoncolburne/better-auth-py), [Rust](https://github.com/jasoncolburne/better-auth-rs)
- Server Only: [Go](https://github.com/jasoncolburne/better-auth-go), [Ruby](https://github.com/jasoncolburne/better-auth-rb)
- Client Only: [Swift](https://github.com/jasoncolburne/better-auth-swift), [Dart](https://github.com/jasoncolburne/better-auth-dart), [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## Repository Structure

This repository is a **git submodule** of the parent [better-auth](https://github.com/jasoncolburne/better-auth) specification repository. The parent repository includes all 8 language implementations as submodules and provides orchestration scripts for cross-implementation testing.

### Standardized Build System

All implementations use standardized `Makefile` targets for consistency:

```bash
make setup          # Install dependencies (npm install)
make test           # Run tests (npm test)
make type-check     # Run type checker (npm run type-check)
make lint           # Run linter (npm run lint)
make format         # Format code (npm run format)
make format-check   # Check formatting (npm run format:check)
make build          # Build project (npm run build)
make clean          # Clean artifacts (rm -rf node_modules dist)
make server         # Run example server (npm run server)
make test-integration  # Run integration tests (npm run test:integration)
```

### Parent Repository Orchestration

The parent repository provides scripts in `scripts/` for running operations across all implementations:

- `scripts/run-setup.sh` - Setup all implementations
- `scripts/run-unit-tests.sh` - Run tests across all implementations
- `scripts/run-type-checks.sh` - Run type checkers across all implementations
- `scripts/run-lints.sh` - Run linters across all implementations
- `scripts/run-format-checks.sh` - Check formatting across all implementations
- `scripts/run-integration-tests.sh` - Run cross-language integration tests
- `scripts/run-all-checks.sh` - Run all checks in sequence
- `scripts/pull-repos.sh` - Update all submodules

These scripts automatically skip implementations where tooling is not available.

## Architecture

### Directory Structure

```
src/
├── api/              # Client and Server implementations
│   ├── client.ts     # BetterAuthClient class
│   ├── server.ts     # BetterAuthServer class
│   └── index.ts
├── interfaces/       # Protocol interfaces (crypto, storage, encoding, I/O)
│   ├── crypto.ts     # IHasher, INoncer, IVerifier, signing/verification keys
│   ├── encoding.ts   # ITimestamper, ITokenEncoder, IIdentityVerifier
│   ├── io.ts         # INetwork interface
│   ├── paths.ts      # IAuthenticationPaths interface
│   ├── storage.ts    # Client and server storage interfaces
│   └── index.ts
├── messages/         # Protocol message types
│   ├── message.ts    # Base message types
│   ├── request.ts    # Base request types
│   ├── response.ts   # Base response types
│   ├── account.ts    # Account protocol messages
│   ├── device.ts     # Device protocol messages
│   ├── session.ts    # Session protocol messages
│   ├── access.ts     # Access protocol messages
│   └── index.ts
├── examples/         # Example server implementation
│   └── server.ts
├── tests/            # Test suite
│   ├── api.test.ts          # API integration tests
│   ├── token.test.ts        # Token encoding tests
│   ├── integration.test.ts  # Cross-implementation integration tests
│   └── implementation/      # Reference implementations of interfaces
└── index.ts          # Main exports
```

### Key Components

**BetterAuthClient** (`src/api/client.ts`)
- Implements all client-side protocol operations
- Manages authentication state and key rotation
- Handles token lifecycle (acquire, refresh)
- Composes crypto, storage, and encoding interfaces

**BetterAuthServer** (`src/api/server.ts`)
- Implements all server-side protocol operations
- Validates requests and manages device state
- Issues and validates tokens
- Composes crypto, storage, and encoding interfaces

**Message Types** (`src/messages/`)
- Strongly typed protocol messages
- Serialization/deserialization support
- Type-safe request/response pairs

**Interfaces** (`src/interfaces/`)
- Define contracts for crypto, storage, encoding, and I/O
- Enable pluggable implementations
- Platform and technology agnostic

## TypeScript-Specific Patterns

### Interface Composition

This implementation heavily uses TypeScript interfaces to define contracts:
- Crypto interfaces (hashing, signing, verification)
- Storage interfaces (client stores, server stores)
- Encoding interfaces (timestamping, token encoding)
- I/O interfaces (network communication)

This allows consumers to bring their own implementations while ensuring type safety.

### Type Safety

All protocol messages are strongly typed with TypeScript interfaces. This provides:
- Compile-time verification of message structure
- IDE autocomplete for message fields
- Refactoring safety

### Async/Await

All operations are asynchronous using `async/await`:
- Client operations return `Promise<T>`
- Server operations return `Promise<Response>`
- Storage operations are async
- Network operations are async

### Class-Based API

The main APIs are class-based:
- `BetterAuthClient` for client operations
- `BetterAuthServer` for server operations

Both classes are configured via dependency injection through their constructors.

## Example Implementations

The `tests/implementation/` directory contains reference implementations:
- CESR encoding/decoding
- Blake3 hashing
- ECDSA P-256 signing/verification
- In-memory storage
- Mock network implementation

These serve as examples for how to implement the protocol interfaces.

## Testing

### Unit Tests (`api.test.ts`)
Complete end-to-end tests covering:
- Account creation, recovery, deletion
- Device linking/unlinking
- Authentication flows
- Access requests
- Key rotation
- Token refresh

### Integration Tests (`integration.test.ts`)
Cross-language integration tests:
- TypeScript client → Go server
- TypeScript client → Python server
- TypeScript client → Ruby server

Run with `npm run test:integration` (requires a server running on localhost:8080).

### Token Tests (`token.test.ts`)
Token encoding/decoding tests to verify CESR format.

## Usage Patterns

### Client Initialization

```typescript
const client = new BetterAuthClient({
  crypto: {
    hasher: yourHasher,
    noncer: yourNoncer,
    responsePublicKey: serverPublicKey,
  },
  encoding: {
    timestamper: yourTimestamper,
  },
  io: {
    network: yourNetwork,
  },
  paths: yourPaths,
  store: {
    identity: identityStore,
    device: deviceStore,
    key: {
      authentication: authKeyStore,
      access: accessKeyStore,
    },
    token: { access: tokenStore },
  },
});
```

### Server Initialization

```typescript
const server = new BetterAuthServer({
  crypto: {
    hasher: yourHasher,
    keyPair: {
      response: responseSigningKey,
      access: accessSigningKey,
    },
    verifier: yourVerifier,
  },
  encoding: {
    identityVerifier: yourIdentityVerifier,
    timestamper: yourTimestamper,
    tokenEncoder: yourTokenEncoder,
  },
  expiry: {
    accessInMinutes: 15,
    refreshInHours: 24,
  },
  store: {
    access: { keyHash: accessKeyHashStore },
    authentication: {
      key: authKeyStore,
      nonce: nonceStore,
    },
    recovery: { hash: recoveryHashStore },
  },
});
```

### Client Operations

```typescript
// Create account
await client.createAccount(recoveryHash);

// Authenticate
await client.authenticate();

// Make access request
const response = await client.makeAccessRequest('/api/resource', { data: 'value' });

// Rotate authentication key
await client.rotateAuthenticationKey();

// Refresh access token
await client.refreshAccessToken();
```

### Server Operations

```typescript
// Handle request
const response = await server.handleRequest(request);
```

## Development Workflow

### Running Tests
```bash
npm test                    # Run all tests
npm run test:integration    # Run integration tests (needs server)
```

### Building
```bash
npm run build              # Build to dist/
```

### Linting & Formatting
```bash
npm run lint               # ESLint
npx prettier --write .     # Format code
```

## Integration with Other Implementations

This TypeScript implementation is used for integration testing with:
- Go server (`better-auth-go`)
- Python server (`better-auth-py`)
- Ruby server (`better-auth-rb`)

The `examples/server.ts` provides a simple HTTP server for testing.

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `npm test`
3. If protocol changes: update the main spec repository
4. If breaking changes: update other implementations
5. Run integration tests to verify cross-language compatibility
6. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `src/api/client.ts` - All client logic
- `src/api/server.ts` - All server logic
- `src/messages/` - Protocol message definitions
- `src/interfaces/` - Interface contracts
- `tests/api.test.ts` - Comprehensive test suite
- `tests/integration.test.ts` - Cross-language tests
