CREATE TYPE registration_mode AS ENUM ('closed', 'allowlist', 'invite', 'open');
CREATE TYPE registration_entry_status AS ENUM ('pending', 'claimed', 'revoked');
CREATE TYPE instance_role AS ENUM ('user', 'admin');
CREATE TYPE namespace_role AS ENUM ('reader', 'writer', 'admin');
CREATE TYPE repository_visibility AS ENUM ('private', 'public');
CREATE TYPE repository_action AS ENUM ('pull', 'push', 'delete', 'admin');
CREATE TYPE upload_status AS ENUM ('uploading', 'finalizing', 'committed', 'failed', 'cancelled');
CREATE TYPE blob_status AS ENUM ('committed', 'tombstoned');

CREATE TABLE instance_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    registration_mode registration_mode NOT NULL DEFAULT 'allowlist',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO instance_settings (singleton) VALUES (TRUE);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL,
    display_name TEXT,
    primary_email TEXT NOT NULL,
    instance_role instance_role NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled_at TIMESTAMPTZ,
    CONSTRAINT users_username_format CHECK (
        username ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'
    )
);

CREATE UNIQUE INDEX users_username_unique_ci ON users (LOWER(username));
CREATE UNIQUE INDEX users_email_unique_ci ON users (LOWER(primary_email));

CREATE TABLE verified_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_subject)
);

CREATE INDEX verified_identities_user_idx ON verified_identities (user_id);

CREATE TABLE registration_entries (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    instance_role instance_role NOT NULL DEFAULT 'user',
    namespace_role namespace_role NOT NULL DEFAULT 'admin',
    status registration_entry_status NOT NULL DEFAULT 'pending',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    claimed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX registration_entries_pending_email_unique
    ON registration_entries (LOWER(email))
    WHERE status = 'pending';

CREATE TABLE namespaces (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT namespaces_name_format CHECK (
        name ~ '^[a-z0-9]+([._-][a-z0-9]+)*$'
    )
);

CREATE UNIQUE INDEX namespaces_name_unique_ci ON namespaces (LOWER(name));

CREATE TABLE namespace_memberships (
    namespace_id UUID NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role namespace_role NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (namespace_id, user_id)
);

CREATE TABLE repositories (
    id UUID PRIMARY KEY,
    namespace_id UUID NOT NULL REFERENCES namespaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    visibility repository_visibility NOT NULL DEFAULT 'private',
    immutable_tag_pattern TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT repositories_name_format CHECK (
        name ~ '^[a-z0-9]+([._/-][a-z0-9]+)*$'
    ),
    UNIQUE (namespace_id, name)
);

CREATE TABLE repository_permissions (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action repository_action NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, user_id, action)
);

CREATE TABLE personal_access_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX personal_access_tokens_user_idx ON personal_access_tokens (user_id);

CREATE TABLE browser_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX browser_sessions_expiry_idx ON browser_sessions (expires_at);

CREATE TABLE oauth_states (
    state_hash TEXT PRIMARY KEY,
    return_to TEXT NOT NULL DEFAULT '/registry',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE blobs (
    digest TEXT PRIMARY KEY,
    size BIGINT NOT NULL CHECK (size >= 0),
    object_key TEXT NOT NULL UNIQUE,
    status blob_status NOT NULL DEFAULT 'committed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tombstoned_at TIMESTAMPTZ
);

CREATE TABLE repository_blobs (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    digest TEXT NOT NULL REFERENCES blobs(digest) ON DELETE RESTRICT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, digest)
);

CREATE TABLE manifests (
    digest TEXT PRIMARY KEY,
    media_type TEXT NOT NULL,
    artifact_type TEXT,
    subject_digest TEXT,
    size BIGINT NOT NULL CHECK (size >= 0),
    payload BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX manifests_subject_idx ON manifests (subject_digest)
    WHERE subject_digest IS NOT NULL;

CREATE TABLE repository_manifests (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    digest TEXT NOT NULL REFERENCES manifests(digest) ON DELETE RESTRICT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    PRIMARY KEY (repository_id, digest)
);

CREATE TABLE descriptor_edges (
    parent_digest TEXT NOT NULL REFERENCES manifests(digest) ON DELETE CASCADE,
    child_digest TEXT NOT NULL,
    relationship TEXT NOT NULL CHECK (
        relationship IN ('config', 'layer', 'manifest', 'subject')
    ),
    position INTEGER NOT NULL CHECK (position >= 0),
    media_type TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    platform JSONB,
    annotations JSONB,
    PRIMARY KEY (parent_digest, relationship, position, child_digest)
);

CREATE INDEX descriptor_edges_child_idx ON descriptor_edges (child_digest);

CREATE TABLE tags (
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    manifest_digest TEXT NOT NULL REFERENCES manifests(digest) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, name)
);

CREATE TABLE tag_events (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    tag_name TEXT NOT NULL,
    previous_digest TEXT,
    new_digest TEXT,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX tag_events_repository_idx
    ON tag_events (repository_id, created_at DESC);

CREATE TABLE upload_sessions (
    id UUID PRIMARY KEY,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    object_key TEXT NOT NULL UNIQUE,
    storage_upload_id TEXT NOT NULL,
    accepted_offset BIGINT NOT NULL DEFAULT 0 CHECK (accepted_offset >= 0),
    next_part_number INTEGER NOT NULL DEFAULT 1 CHECK (next_part_number > 0),
    uniform_part_size BIGINT CHECK (uniform_part_size > 0),
    status upload_status NOT NULL DEFAULT 'uploading',
    error_message TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX upload_sessions_expiry_idx
    ON upload_sessions (status, expires_at);

CREATE TABLE upload_parts (
    upload_id UUID NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
    part_number INTEGER NOT NULL CHECK (part_number > 0),
    etag TEXT NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (upload_id, part_number)
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    repository_id UUID REFERENCES repositories(id) ON DELETE SET NULL,
    resource_type TEXT,
    resource_id TEXT,
    detail JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_events_created_idx ON audit_events (created_at DESC);
