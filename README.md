# better-auth-ts

**Reference TypeScript implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This is the canonical implementation that defines protocol behavior and generates the CESR-encoded examples in the specification.

## What's Included

- ✅ **Client + Server** - Full protocol implementation
- ✅ **Reference Implementation** - Other language ports follow this implementation
- ✅ **CESR Encoding** - Generates spec examples
- ✅ **Complete Test Suite** - Unit and integration tests
- ✅ **Example Server** - HTTP server for integration testing

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # Install dependencies
```

### Running Tests

```bash
make test           # Run unit tests
make type-check     # Run TypeScript type checker
make lint           # Run linter
make format-check   # Check code formatting
```

### Running Example Server

```bash
make server         # Start HTTP server on localhost:8080
```

### Integration Testing

```bash
# Start a server (TypeScript, Python, Rust, Go, or Ruby)
make server

# In another terminal, run integration tests
make test-integration
```

## Development

This implementation uses:
- **TypeScript** for type safety
- **Vitest** for testing
- **ESLint** for linting
- **Prettier** for formatting

All development commands use standardized `make` targets:

```bash
make setup          # Install npm packages
make test           # Run tests
make type-check     # Type check with tsc
make lint           # Lint with ESLint
make format         # Format code with Prettier
make format-check   # Check formatting
make build          # Build to dist/
make clean          # Remove node_modules and dist/
make server         # Run example server
make test-integration  # Run integration tests
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- TypeScript-specific patterns
- Interface composition and type safety
- Usage examples and API patterns

## Integration with Other Implementations

This TypeScript client is used in integration tests with:
- **TypeScript server** (better-auth-ts) - This repository
- **Python server** (better-auth-py)
- **Rust server** (better-auth-rs)
- **Go server** (better-auth-go)
- **Ruby server** (better-auth-rb)

See `src/tests/integration.test.ts` for cross-language integration tests.

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - **This repository** (reference)
- [Python](https://github.com/jasoncolburne/better-auth-py)
- [Rust](https://github.com/jasoncolburne/better-auth-rs)

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go)
- [Ruby](https://github.com/jasoncolburne/better-auth-rb)

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift)
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## License

MIT
