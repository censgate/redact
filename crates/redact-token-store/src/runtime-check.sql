-- Read-only preflight/readiness. Exact v1 isolation policies are intentional:
-- extra permissive policies or direct partition grants can bypass the parent.
-- Inspect the whole membership closure of both effective and login identities.
-- INHERIT FALSE does not prevent SET ROLE. Conservatively include SET FALSE
-- edges too: this is portable across pre-16 and 16+ membership catalogs and
-- rejects privileged group membership without depending on mutable edge options.
WITH RECURSIVE runtime_roles(oid) AS (
    SELECT oid FROM pg_roles WHERE rolname IN (current_user,session_user)
    UNION
    SELECT m.roleid FROM pg_auth_members m JOIN runtime_roles r ON m.member=r.oid
), parents AS (
    SELECT c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='redact_tokens_v1' AND c.relkind='p'
      AND c.relname IN ('contexts','entries','aliases')
), policies AS (
    SELECT p.* FROM pg_policy p JOIN parents t ON t.oid=p.polrelid
)
SELECT
    NOT EXISTS (
        SELECT 1 FROM runtime_roles r JOIN pg_roles p USING (oid)
        WHERE p.rolsuper OR p.rolbypassrls OR p.rolcreaterole OR p.rolreplication
    )
    AND has_schema_privilege('redact_tokens_v1','USAGE')
    AND NOT EXISTS (
        SELECT 1 FROM runtime_roles r
        WHERE has_schema_privilege(r.oid,'redact_tokens_v1','CREATE')
    )
    AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='redact_tokens_v1' AND c.relowner IN (SELECT oid FROM runtime_roles)
    )
    AND (SELECT count(*)=3 AND bool_and(
        relrowsecurity AND relforcerowsecurity
        AND has_table_privilege(oid,'SELECT') AND has_table_privilege(oid,'INSERT')
        AND has_table_privilege(oid,'UPDATE') AND has_table_privilege(oid,'DELETE')) FROM parents)
    AND NOT EXISTS (
        SELECT 1 FROM parents p CROSS JOIN runtime_roles r
        WHERE has_table_privilege(r.oid,p.oid,'TRUNCATE')
    )
    AND (SELECT count(*)=3 AND bool_and(
        polname='tenant_isolation' AND polcmd='*' AND polpermissive AND polroles='{0}'::oid[]
        AND pg_get_expr(polqual,polrelid)='(tenant = current_setting(''redact.tenant''::text, true))'
        AND pg_get_expr(polwithcheck,polrelid)='(tenant = current_setting(''redact.tenant''::text, true))'
    ) FROM policies)
    AND NOT EXISTS (
        SELECT 1 FROM pg_inherits i JOIN parents p ON p.oid=i.inhparent
        CROSS JOIN runtime_roles r
        WHERE has_table_privilege(r.oid,i.inhrelid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
           OR has_any_column_privilege(r.oid,i.inhrelid,'SELECT,INSERT,UPDATE')
    )
    AND has_table_privilege('redact_tokens_v1.configuration','SELECT')
    AND NOT EXISTS (
        SELECT 1 FROM runtime_roles r
        WHERE has_table_privilege(r.oid,'redact_tokens_v1.configuration','INSERT,UPDATE,DELETE,TRUNCATE')
           OR has_any_column_privilege(r.oid,'redact_tokens_v1.configuration','INSERT,UPDATE')
    )
;
