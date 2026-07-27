# ADR 0002: Model Jose as a normal account

- Status: accepted

## Decision

The initial `jose` account is created through the ordinary verified-identity
registration transaction. A configuration-seeded allowlist entry reserves its
username and namespace and assigns normal instance and namespace roles.

Registration policy is data/configuration, not a conditional compiled around a
specific email. Future users are enabled by changing policy or adding
invitations.
