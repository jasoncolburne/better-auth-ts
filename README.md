# better-auth-ts
reference typescript implementation of [better auth](https://github.com/jasoncolburne/better-auth)

Better-auth is designed to be agnostic of encoding, cryptographic choice, and storage mechanism.
It simply composes cryptographic and storage interfaces that you provide. In-memory/software
examples exist in the test directory.

Examine `src/tests/api.test.ts` and `src/interfaces` for a start.

## Integration

Check `src/tests/integration.test.ts` and execute it with `npm run test:integration`. It should fail
if you don't have a server running at http://localhost:8080.

To run the example server in golang, for example, check out the
[golang](https://github.com/jasoncolburne/better-auth-go) implementation and start with
`go run examples/server.go`.

After starting the golang server, run the integration tests in another shell.
