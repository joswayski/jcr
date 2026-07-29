# JCR

JCR is Jose's Container Registry: an OCI Distribution-compatible registry and
a first-party Rust push client designed for a privately hosted origin.

The server remains compatible with standard Docker/OCI authentication and
pulls. The `jcr` client adds deterministic, resumable 64 MiB layer uploads so
large pushes can traverse HTTP proxies with bounded request sizes without
introducing a custom image format.

## Workspace

- `jcrd` — OCI registry, token service, metadata API, and web UI.
- `jcr` — Docker-credential-compatible login and chunked push client.
- `jcr-core` — shared digest, manifest, reference, scope, and storage types.

The complete product boundary, acceptance criteria, and non-goals are recorded
in [`docs/PLAN.md`](docs/PLAN.md). Architectural decisions live in
[`docs/adr`](docs/adr).

## Local development

Requirements:

- Rust 1.94 or newer
- Docker with Compose

Start PostgreSQL and Garage:

```console
docker compose up -d
```

Compose runs the two local dependencies; run `jcrd` on the host with Cargo.

Copy `.env.example` to `.env`. Generate a JWT secret, then set
`JCR_ADMIN_EMAIL` to the Google account that should be allowed to register:

```console
cp .env.example .env
openssl rand -hex 32
```

Create a [Google OAuth client](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred)
with the **Web application** type and add this exact authorized redirect URI:

```text
http://127.0.0.1:5000/registry/auth/callback
```

Put its client ID and secret in `.env`:

```dotenv
JCR_JWT_SECRET=paste-the-generated-value
JCR_ADMIN_EMAIL=you@example.com
JCR_GOOGLE_CLIENT_ID=your-client-id
JCR_GOOGLE_CLIENT_SECRET=your-client-secret
JCR_GOOGLE_REDIRECT_URL=http://127.0.0.1:5000/registry/auth/callback
```

`jcrd` loads `.env` automatically for local development.

Configure the local Garage bucket:

```dotenv
JCR_BUCKET_ENDPOINT=http://127.0.0.1:9000
JCR_BUCKET_REGION=garage
JCR_BUCKET_NAME=jcr
JCR_BUCKET_ACCESS_KEY_ID=GK0123456789abcdef0123456789abcdef
JCR_BUCKET_SECRET_ACCESS_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
JCR_BUCKET_FORCE_PATH_STYLE=true
```

Start the server:

```console
cargo run -p jcrd
```

Open `http://127.0.0.1:5000/registry`, continue with the configured Google
account, and choose a username. JCR creates the account and matching personal
namespace in the normal registration transaction. No account or username is
created or reserved by default. Every other identity is rejected in the
default `allowlist` mode without creating a user.

## Using the clients

Create a personal access token in the `/registry` web UI, then use it with
either client.

```console
jcr login 127.0.0.1:5000 --username YOUR_USERNAME
docker login 127.0.0.1:5000 --username YOUR_USERNAME
```

Credentials written by either command use Docker's configured credential
helper and are readable by the other.

Push a single-platform image from the local Docker Engine:

```console
cargo run -p jcr -- push \
  local-image:latest \
  127.0.0.1:5000/YOUR_USERNAME/app:latest
```

Push a single- or multi-platform OCI archive:

```console
cargo run -p jcr -- push \
  --oci-archive ./image.tar \
  127.0.0.1:5000/YOUR_USERNAME/app:latest
```

Different blobs upload concurrently. Each blob uses ordered 64 MiB `PATCH`
requests, a final `PUT`, transient-failure retries, and persisted resume state.
The result is an ordinary OCI image, so pulls use standard clients:

```console
docker pull 127.0.0.1:5000/YOUR_USERNAME/app:latest
```

## Storage configuration

The `bucket` backend uses the S3-compatible API implemented by providers such as
Garage and R2; it does not require AWS S3. Switching providers is configuration
only: endpoint, region, bucket name, credentials, and path-style behavior. No
provider-specific behavior exists in the registry domain model.

Committed blob bytes live in the configured object store. PostgreSQL stores
identity, authorization, repository, upload, descriptor, tag-history, and
audit metadata.

## Verification

The normal local suite includes unit tests plus the PostgreSQL registry flow and
the first-party client passing through a reverse proxy capped at
[Cloudflare's 100 MB request limit](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/4xx-client-error/error-413/):

```console
JCR_DATABASE_URL=postgres://jcr:jcr@127.0.0.1:5432/jcr \
  cargo test --workspace --all-features
```

Exercise the bucket adapter against local Garage:

```console
JCR_TEST_BUCKET_ENDPOINT=http://127.0.0.1:9000 \
JCR_TEST_BUCKET_REGION=garage \
JCR_TEST_BUCKET_NAME=jcr \
JCR_TEST_BUCKET_ACCESS_KEY_ID=GK0123456789abcdef0123456789abcdef \
JCR_TEST_BUCKET_SECRET_ACCESS_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
JCR_TEST_BUCKET_FORCE_PATH_STYLE=true \
  cargo test -p jcrd storage::bucket::tests -- --nocapture
```

The same variables can target an explicitly disposable R2 bucket. Do not point
the test at a bucket containing data you need.

The integration flow has opt-in compatibility gates:

- `JCR_TEST_DOCKER_CLIENT=1` runs real Docker login, credential
  interoperability, push, and pull.
- `JCR_TEST_CONFORMANCE_BINARY=/path/to/conformance.test` runs the official OCI
  Distribution conformance binary with the advertised pull and push categories.
- `JCR_LARGE_TEST_MIB=500` or `1024` generates an incompressible layer of that
  size and sends it through the 100 MB-capped proxy.

For example:

```console
JCR_DATABASE_URL=postgres://jcr:jcr@127.0.0.1:5432/jcr \
JCR_TEST_DOCKER_CLIENT=1 \
JCR_LARGE_TEST_MIB=500 \
  cargo test -p jcrd \
  app::tests::postgres_registry_flow_when_database_is_configured \
  -- --nocapture
```

CI runs formatting, strict Clippy, Garage integration, stock Docker
compatibility, the PostgreSQL flow, and the pinned OCI Distribution v1.1.1
pull/push conformance suite.
