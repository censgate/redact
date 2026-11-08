-- Read-only preflight/readiness. Exact v1 isolation policies are intentional:
-- extra permissive policies or direct partition grants can bypass the parent.
WITH parents AS (
    SELECT c.oid,c.relowner,c.relrowsecurity,c.relforcerowsecurity
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='redact_tokens_v1' AND c.relkind='p'
      AND c.relname IN ('contexts','entries','aliases')
), policies AS (
    SELECT p.* FROM pg_policy p JOIN parents t ON t.oid=p.polrelid
)
SELECT
    (SELECT NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user)
    AND has_schema_privilege('redact_tokens_v1','USAGE')
    AND NOT has_schema_privilege('redact_tokens_v1','CREATE')
    AND NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='redact_tokens_v1' AND pg_has_role(c.relowner,'MEMBER')
    )
    AND (SELECT count(*)=3 AND bool_and(
        relrowsecurity AND relforcerowsecurity
        AND has_table_privilege(oid,'SELECT') AND has_table_privilege(oid,'INSERT')
        AND has_table_privilege(oid,'UPDATE') AND has_table_privilege(oid,'DELETE')
        AND NOT has_table_privilege(oid,'TRUNCATE')) FROM parents)
    AND (SELECT count(*)=3 AND bool_and(
        polname='tenant_isolation' AND polcmd='*' AND polpermissive AND polroles='{0}'::oid[]
        AND pg_get_expr(polqual,polrelid)='(tenant = current_setting(''redact.tenant''::text, true))'
        AND pg_get_expr(polwithcheck,polrelid)='(tenant = current_setting(''redact.tenant''::text, true))'
    ) FROM policies)
    AND NOT EXISTS (
        SELECT 1 FROM pg_inherits i JOIN parents p ON p.oid=i.inhparent
        WHERE has_table_privilege(i.inhrelid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
           OR has_any_column_privilege(i.inhrelid,'SELECT,INSERT,UPDATE')
    )
    AND has_table_privilege('redact_tokens_v1.configuration','SELECT')
    AND NOT has_table_privilege('redact_tokens_v1.configuration','INSERT,UPDATE,DELETE,TRUNCATE')
    AND NOT has_any_column_privilege('redact_tokens_v1.configuration','INSERT,UPDATE')
;
