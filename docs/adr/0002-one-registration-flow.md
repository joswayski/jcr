# ADR 0002: Use one registration flow

- Status: accepted

## Decision

JCR never creates a user, namespace, or reserved username from source-code or
migration defaults. Registration policy determines whether a verified identity
may sign up. Every eligible new user chooses a username, then JCR creates the
account and matching personal namespace in one transaction.

`JCR_ADMIN_EMAIL` may add a pending administrator registration for a verified
email. This grants eligibility and roles only; that person still completes the
same signup flow as any future invited or open-registration user.
