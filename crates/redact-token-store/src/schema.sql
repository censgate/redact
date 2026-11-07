-- Apply with a migration role, never the runtime role. Forward-only v1 schema.
CREATE SCHEMA IF NOT EXISTS redact_tokens_v1;
CREATE TABLE IF NOT EXISTS redact_tokens_v1.contexts (
    tenant text NOT NULL, context text NOT NULL, retired boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant, context)
) PARTITION BY HASH (tenant, context);
CREATE TABLE IF NOT EXISTS redact_tokens_v1.entries (
    tenant text NOT NULL, context text NOT NULL, fingerprint text NOT NULL,
    token text NOT NULL, sealed text NOT NULL, expires_ms bigint NOT NULL,
    PRIMARY KEY (fingerprint, tenant, context), UNIQUE (token, tenant, context),
    FOREIGN KEY (tenant, context) REFERENCES redact_tokens_v1.contexts(tenant, context)
) PARTITION BY HASH (tenant, context);
DO $$ BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS redact_tokens_v1.contexts_p%s PARTITION OF redact_tokens_v1.contexts FOR VALUES WITH (MODULUS 16, REMAINDER %s)', i, i);
        EXECUTE format('CREATE TABLE IF NOT EXISTS redact_tokens_v1.entries_p%s PARTITION OF redact_tokens_v1.entries FOR VALUES WITH (MODULUS 16, REMAINDER %s)', i, i);
    END LOOP;
END $$;
-- An explicit scope expression keeps retirement indexed without offering a
-- misleading prefix-only access path to fresh-partition point-lookup plans.
CREATE INDEX IF NOT EXISTS entries_scope_idx ON redact_tokens_v1.entries
    ((tenant || ':' || context), tenant, context);
ALTER TABLE redact_tokens_v1.contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE redact_tokens_v1.contexts FORCE ROW LEVEL SECURITY;
ALTER TABLE redact_tokens_v1.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE redact_tokens_v1.entries FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='redact_tokens_v1' AND tablename='contexts' AND policyname='tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON redact_tokens_v1.contexts
            USING (tenant = current_setting('redact.tenant', true))
            WITH CHECK (tenant = current_setting('redact.tenant', true));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='redact_tokens_v1' AND tablename='entries' AND policyname='tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON redact_tokens_v1.entries
            USING (tenant = current_setting('redact.tenant', true))
            WITH CHECK (tenant = current_setting('redact.tenant', true));
    END IF;
END $$;
-- Grant USAGE on the schema and SELECT/INSERT/UPDATE/DELETE on the two parent
-- tables only to a dedicated NOSUPERUSER NOBYPASSRLS runtime role. Do not grant
-- access directly to partitions, schema CREATE, ownership, or migration rights.
