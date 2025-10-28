# BetterAuth Cloudflare Worker Example

This directory contains a Cloudflare Worker implementation of the BetterAuth server, used for running integration tests and validating the protocol end-to-end.

Overview
The `worker.ts` script implements a Cloudflare Worker server via `workerd` that exposes the BetterAuth API routes using `BetterAuthServer` and `AccessVerifier`.

These routes handle user account operations, device management, session creation, and validation of access requests.

The configuration for serving the Worker locally via **Workerd** is defined in `worker.config.capnp`.

Integration tests in `src/tests/integration.test.ts` can use this worker as the backend for full authentication cycles.

## Building and Running Locally

### Build the Worker

`npm run build:worker`

This compiles worker.ts into examples/worker/dist/worker.js.

### Start the Worker

`npm run server:worker`

This runs workerd using the configuration in worker.config.capnp, serving locally on http://localhost:8080.

### Run Integration Tests

In another terminal window:

`npm run test:integration`

The tests will connect to the running worker instance and validate authentication flows such as account creation, session management, and recovery.
