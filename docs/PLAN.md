# JCR MVP plan

## Summary

Build only the JCR application in this repository:

- A Rust OCI registry server named `jcrd`.
- A Rust client named `jcr`.
- A minimal web UI.
- PostgreSQL metadata and an S3-compatible blob-storage adapter targeting R2.
- Standards-compatible Docker/OCI authentication and pulls.
- First-party chunked pushes that work beneath Cloudflare's request limit.

Do not provision or modify any production infrastructure. The mini-PC plan
belongs in a future infrastructure repository or task.

## Identity and authentication

- Model `jose` as a normal user with a normal personal namespace named `jose`.
- Store users, verified identities, namespaces, memberships, repository
  permissions, personal access tokens, and registration invitations/allowlist
  entries in PostgreSQL.
- Use configurable registration modes: `closed`, `allowlist`, `invite`, and
  `open`.
- Default v1 to `allowlist`, containing only Jose's configured, verified Google
  email.
- Seed the allowlist with username `jose`, namespace `jose`, namespace role
  `admin`, and instance role `admin`.
- On first Google login, run the same account-creation transaction future
  invited users will use; the allowlist entry supplies the preassigned username
  and roles.
- Reject every other email without creating a partial user record.
- Use secure browser sessions for the UI and personal access tokens for Docker,
  the JCR CLI, and CI.
- Hash PATs with Argon2id, show secrets once, support expiration/revocation, and
  record last use.
- Implement Docker's bearer-token challenge with repository-scoped `pull`,
  `push`, `delete`, and `admin` actions.
- Allow anonymous pulls only from public repositories.

## Registry, storage, and web interfaces

### OCI server

Implement:

- `/v2/` authentication/capability check.
- Blob existence, download, upload initialization, chunk upload, status,
  completion, and cancellation.
- Manifest and multi-platform index upload/download by tag or digest.
- Tag listing, mutation history, and manifest deletion.
- Public/private repositories.
- Exact digest validation and content-addressed deduplication.
- Generic manifest reference and `subject` relationships for future OCI
  referrers.
- Delayed garbage collection so shared layers are never removed immediately.

Committed blobs live in an S3-compatible object store. Put all provider behavior
behind a `BlobStore` interface and test it against Garage locally; R2 is
selected later through endpoint and credential configuration without
R2-specific domain logic.

PostgreSQL stores accounts, permissions, repositories, upload sessions, blob
metadata, manifests, descriptor relationships, tags, and audit events.

### Web UI

Serve a small UI from `jcrd` under `/registry` so it can eventually be mounted
at `josevalerio.com/registry` without requiring that deployment now.

It provides:

- Google login.
- Repository creation and visibility controls.
- PAT creation and revocation.
- Repository tags and manifest history.
- Storage usage and active/failed uploads.
- Audit events.

The OCI endpoint remains logically separate at `registry.josevalerio.com`, but
no DNS or Cloudflare changes are part of this work.

### CLI

Implement:

- `jcr login REGISTRY`
- `jcr logout REGISTRY`
- `jcr push LOCAL_IMAGE REMOTE_REFERENCE`
- `jcr push --oci-archive PATH REMOTE_REFERENCE`

`jcr login` validates a PAT and writes through the configured Docker credential
helper. Credentials created by `docker login` must also be readable by `jcr`.

`jcr push`:

- Reads a single-platform image from the local Docker Engine or a multi-platform
  OCI archive.
- Checks which blobs already exist.
- Uploads different blobs concurrently.
- Uploads each individual blob sequentially in uniform 64 MiB OCI `PATCH`
  requests.
- Shows progress and retries transient failures.
- Resumes from the registry-reported offset.
- Produces ordinary OCI objects that standard Docker/containerd clients can
  subsequently pull.

Do not implement `jcr pull` in v1; standard clients already provide it.

## Implementation sequence

1. Add this plan, architecture decisions, the Cargo workspace, local
   PostgreSQL/Garage development services, configuration loading, migrations,
   and CI checks.
2. Implement the metadata model, bucket storage abstraction, digest handling,
   and core OCI pull endpoints.
3. Implement normal user creation, Google allowlisting, browser sessions, PATs,
   bearer-token exchange, and repository authorization.
4. Implement resumable OCI upload sessions, R2 multipart translation, digest
   finalization, deduplication, and cleanup.
5. Implement local-Docker and OCI-archive support in `jcr push`, followed by
   credential interoperability and progress/resume behavior.
6. Add the `/registry` web UI, tag history, deletion, audit events, and
   delayed garbage collection.
7. Complete conformance and compatibility testing; stop without deploying
   externally.

## Test and acceptance criteria

- Jose's allowed Google identity creates a regular `jose` user and namespace
  through the standard account flow.
- A different valid Google identity is denied and leaves no user record.
- Changing registration configuration—not application code—allows a second
  invited user.
- `docker login registry-host` succeeds using `jose` plus a PAT.
- Anonymous public pulls succeed; anonymous private pulls and all anonymous
  pushes fail.
- Repository-scoped tokens cannot access another repository.
- Credentials written by `jcr login` work with `docker pull`, and Docker-stored
  credentials work with `jcr push`.
- Docker, Podman, nerdctl/containerd, crane, and ORAS can pull supported
  manifests and indexes.
- Stock `docker push` works for requests within the local proxy limit but is not
  the supported large-upload path.
- `jcr push` successfully uploads generated 500 MiB and 1 GiB incompressible
  layers through a local reverse proxy capped at Cloudflare Free/Pro's
  100,000,000-byte per-request limit. These fixture sizes are not maximum blob
  sizes.
- Interrupted uploads resume without retransmitting acknowledged chunks,
  including after a `jcrd` restart.
- Incorrect digests, out-of-order chunks, expired sessions, revoked PATs, and
  malformed manifests are rejected.
- Shared blobs survive deletion of one referencing tag or repository.
- The OCI Distribution conformance suite passes for the advertised pull and
  push categories.
- The same storage integration suite passes against Garage and an explicitly
  configured disposable R2 test bucket.

## Explicitly out of scope

- Plugging in, configuring, or accessing the mini-PC.
- Ubuntu, Tailscale, k3s, Kubernetes, containerd configuration, or
  orchestration.
- Railway changes or application migration.
- PostgreSQL operational backups or backup verification.
- Production DNS, Cloudflare Tunnel, or R2 provisioning.
- A public upload gateway.
- Public signup, organizations, teams, billing, scanning, signing, replication,
  or pull-through caching.
- A custom container orchestrator.
