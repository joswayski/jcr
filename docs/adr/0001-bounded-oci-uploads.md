# ADR 0001: Use a first-party client for bounded OCI uploads

- Status: accepted

## Context

Cloudflare's proxied HTTP request limit applies to each request before it
reaches the registry. OCI permits a blob to be uploaded using multiple ordered
`PATCH` requests, but common clients may send an entire compressed layer in one
request.

## Decision

JCR remains an OCI-compatible registry. Its first-party `jcr push` client uses
the standard `POST`, ordered `PATCH`, and final `PUT` upload sequence with
uniform 64 MiB requests. No custom image or manifest format is introduced.

Standard clients remain supported for login, pulls, and pushes whose request
shape fits the ingress. Large tunneled uploads use `jcr push`.

## Consequences

The server must persist upload offsets and storage-part metadata. The CLI must
read local Docker images and OCI archives, use Docker-compatible credentials,
and resume uploads. A future public service can add a separate upload gateway
without changing stored content.
