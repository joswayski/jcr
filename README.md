# JCR

JCR is Jose's Container Registry: an OCI Distribution-compatible registry and
a first-party Rust push client designed for a privately hosted origin.

The server remains compatible with standard Docker/OCI authentication and
pulls. The `jcr` client adds deterministic, resumable 64 MiB layer uploads so
large pushes can traverse HTTP proxies with bounded request sizes without
introducing a custom image format.

This repository is intentionally scoped to the registry application. It does
not configure a home server, Kubernetes, Cloudflare, Railway, backups, or
application migrations.

## Workspace

- `jcrd` — OCI registry, token service, metadata API, and owner web UI.
- `jcr` — Docker-credential-compatible login and chunked push client.
- `jcr-core` — shared digest, manifest, reference, scope, and storage types.

The complete product boundary, acceptance criteria, and non-goals are recorded
in [`docs/PLAN.md`](docs/PLAN.md). Architectural decisions live in
[`docs/adr`](docs/adr).

## Local development

Requirements:

- Rust 1.94 or newer
- Docker with Compose

Start PostgreSQL and MinIO:

```console
docker compose up -d
```

Copy `.env.example` to `.env`. Replace the JWT secret and bootstrap email with
real values. `jcrd` loads this file automatically for local development.

The zero-dependency development default stores blobs on the filesystem. To run
the application against MinIO instead, set:

```dotenv
JCR_STORAGE_BACKEND=s3
JCR_S3_ENDPOINT=http://127.0.0.1:9000
JCR_S3_REGION=us-east-1
JCR_S3_BUCKET=jcr
JCR_S3_ACCESS_KEY_ID=minio
JCR_S3_SECRET_ACCESS_KEY=minio-password
JCR_S3_FORCE_PATH_STYLE=true
```

Start the server:

```console
cargo run -p jcrd
```

The local registry listens on `http://127.0.0.1:5000`, and its owner UI is at
`http://127.0.0.1:5000/registry`.

Google login is enabled only when all three Google OAuth settings in
`.env.example` are present. The first verified login matching
`JCR_BOOTSTRAP_EMAIL` creates the ordinary `jose` account and namespace. Every
other identity is rejected in the default `allowlist` mode without creating a
user.

## Using the clients

Create a personal access token in the owner UI, then use it with either client.

```console
jcr login 127.0.0.1:5000 --username jose
docker login 127.0.0.1:5000 --username jose
```

Credentials written by either command use Docker's configured credential
helper and are readable by the other.

Push a single-platform image from the local Docker Engine:

```console
cargo run -p jcr -- push local-image:latest 127.0.0.1:5000/jose/app:latest
```

Push a single- or multi-platform OCI archive:

```console
cargo run -p jcr -- push \
  --oci-archive ./image.tar \
  127.0.0.1:5000/jose/app:latest
```

Different blobs upload concurrently. Each blob uses ordered 64 MiB `PATCH`
requests, a final `PUT`, transient-failure retries, and persisted resume state.
The result is an ordinary OCI image, so pulls use standard clients:

```console
docker pull 127.0.0.1:5000/jose/app:latest
```

## Storage configuration

R2 uses the same `s3` backend as MinIO. Switching providers is configuration
only: endpoint, region, bucket, credentials, and path-style behavior. No
R2-specific behavior exists in the registry domain model.

Committed blob bytes live in the configured object store. PostgreSQL stores
identity, authorization, repository, upload, descriptor, tag-history, and
audit metadata.

## Verification

The normal local suite includes unit tests plus the PostgreSQL registry flow and
the first-party client passing through a reverse proxy capped at 100 MB:

```console
JCR_DATABASE_URL=postgres://jcr:jcr@127.0.0.1:5432/jcr \
  cargo test --workspace --all-features
```

Exercise the S3 adapter against local MinIO:

```console
JCR_TEST_S3_ENDPOINT=http://127.0.0.1:9000 \
JCR_TEST_S3_REGION=us-east-1 \
JCR_TEST_S3_BUCKET=jcr \
JCR_TEST_S3_ACCESS_KEY_ID=minio \
JCR_TEST_S3_SECRET_ACCESS_KEY=minio-password \
JCR_TEST_S3_FORCE_PATH_STYLE=true \
  cargo test -p jcrd storage::s3::tests -- --nocapture
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

CI runs formatting, strict Clippy, MinIO integration, stock Docker
compatibility, the PostgreSQL flow, and the pinned OCI Distribution v1.1.1
pull/push conformance suite. Production deployment is deliberately not part of
this repository.
