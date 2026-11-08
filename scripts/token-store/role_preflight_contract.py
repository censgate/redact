"""Assumable-role regressions, only in the harness-owned throwaway cluster."""
import re


def exercise(sql, check, runtime_check):
    reader = 'token_fixture_role_reader'
    bridge_a = 'token_fixture_role_bridge_a'
    bridge_b = 'token_fixture_role_bridge_b'
    version = int(sql(1, 'SHOW server_version_num').strip())
    # PG16 added per-membership INHERIT/SET options. Earlier versions use the
    # member's NOINHERIT attribute and permit switching through membership.
    options = ' WITH INHERIT FALSE, SET TRUE' if version >= 160000 else ''
    sql(1, f'CREATE ROLE {reader} NOLOGIN NOINHERIT; '
           f'CREATE ROLE {bridge_a} NOLOGIN NOINHERIT; '
           f'CREATE ROLE {bridge_b} NOLOGIN NOINHERIT; '
           'ALTER ROLE token_runtime NOINHERIT')
    try:
        sql(1, f'GRANT USAGE ON SCHEMA redact_tokens_v1 TO {reader}; '
               f'GRANT SELECT ON redact_tokens_v1.contexts TO {reader}')
        sql(1, "INSERT INTO redact_tokens_v1.contexts(tenant,context) "
               "VALUES ('synthetic-foreign-role-fixture','synthetic-role-context')")
        partition = sql(1, "SELECT tableoid::regclass FROM redact_tokens_v1.contexts "
                           "WHERE tenant='synthetic-foreign-role-fixture'").strip()
        assert re.fullmatch(r'redact_tokens_v1\.contexts_p[0-9]+', partition)
        login = "SET SESSION AUTHORIZATION token_runtime; SET redact.tenant='synthetic-visible'; "
        assert sql(1, login + 'SELECT count(tenant) FROM redact_tokens_v1.contexts').splitlines()[-1] == '0'

        def switched(query):
            return sql(1, login + f'SET ROLE {reader}; ' + query).splitlines()[-1]

        # These grants do not change the runtime role's own privilege flags or
        # inherited privileges. SET ROLE still exposes the unsafe capability.
        cases = [
            (f'ALTER ROLE {reader} BYPASSRLS', f'ALTER ROLE {reader} NOBYPASSRLS',
             'SELECT count(tenant) FROM redact_tokens_v1.contexts'),
            (f'GRANT SELECT ON {partition} TO {reader}', f'REVOKE SELECT ON {partition} FROM {reader}',
             f'SELECT count(tenant) FROM {partition}'),
            (f'GRANT SELECT(tenant) ON {partition} TO {reader}', f'REVOKE SELECT(tenant) ON {partition} FROM {reader}',
             f'SELECT count(tenant) FROM {partition}'),
            (f'GRANT UPDATE ON redact_tokens_v1.configuration TO {reader}',
             f'REVOKE UPDATE ON redact_tokens_v1.configuration FROM {reader}',
             "SELECT has_table_privilege(current_user,'redact_tokens_v1.configuration','UPDATE')::int"),
            (f'GRANT UPDATE(commitment) ON redact_tokens_v1.configuration TO {reader}',
             f'REVOKE UPDATE(commitment) ON redact_tokens_v1.configuration FROM {reader}',
             "SELECT has_column_privilege(current_user,'redact_tokens_v1.configuration','commitment','UPDATE')::int"),
            (f'GRANT CREATE ON SCHEMA redact_tokens_v1 TO {reader}',
             f'REVOKE CREATE ON SCHEMA redact_tokens_v1 FROM {reader}',
             "SELECT has_schema_privilege(current_user,'redact_tokens_v1','CREATE')::int"),
            (f'GRANT TRUNCATE ON redact_tokens_v1.contexts TO {reader}',
             f'REVOKE TRUNCATE ON redact_tokens_v1.contexts FROM {reader}',
             "SELECT has_table_privilege(current_user,'redact_tokens_v1.contexts','TRUNCATE')::int"),
            (f'ALTER ROLE {reader} CREATEROLE', f'ALTER ROLE {reader} NOCREATEROLE',
             'SELECT rolcreaterole::int FROM pg_roles WHERE rolname=current_user'),
            (f'ALTER ROLE {reader} REPLICATION', f'ALTER ROLE {reader} NOREPLICATION',
             'SELECT rolreplication::int FROM pg_roles WHERE rolname=current_user'),
        ]
        for edges in [[(reader, 'token_runtime')],
                      [(reader, bridge_b), (bridge_b, bridge_a), (bridge_a, 'token_runtime')]]:
            for parent, member in edges:
                sql(1, f'GRANT {parent} TO {member}{options}')
            try:
                assert sql(1, f"SELECT pg_has_role('token_runtime','{reader}','USAGE')").strip() == 'f'
                check(True)  # Harmless non-inheriting group membership is valid.
                for broken, repaired, proof in cases:
                    sql(1, broken)
                    try:
                        assert switched(proof) == '1', 'fixture did not demonstrate SET ROLE capability'
                        check(False)
                    finally:
                        sql(1, repaired)
                    check(True)
            finally:
                for parent, member in reversed(edges):
                    sql(1, f'REVOKE {parent} FROM {member}')
        if version >= 160000:
            sql(1, f'GRANT {reader} TO token_runtime WITH INHERIT FALSE, SET FALSE; '
                   f'ALTER ROLE {reader} BYPASSRLS')
            try:
                assert sql(1, f"SELECT pg_has_role('token_runtime','{reader}','SET')").strip() == 'f'
                check(False)  # Documented conservative policy includes blocked edges.
            finally:
                sql(1, f'REVOKE {reader} FROM token_runtime; ALTER ROLE {reader} NOBYPASSRLS')
        # A safe current_user must not mask a privileged session_user which can
        # be recovered via RESET ROLE. Exercise the exact production SQL.
        sql(1, f'GRANT token_runtime TO {reader}{options}; ALTER ROLE {reader} BYPASSRLS')
        try:
            result = sql(1, f'SET SESSION AUTHORIZATION {reader}; SET ROLE token_runtime; ' + runtime_check)
            assert result.splitlines()[-1] == 'f', 'privileged login identity escaped validation'
        finally:
            sql(1, f'REVOKE token_runtime FROM {reader}; ALTER ROLE {reader} NOBYPASSRLS')
        print('Role preflight: 18 direct/multi-hop capability rejections, safe membership, '
              'blocked SET edge and privileged login identity passed')
    finally:
        sql(1, "DELETE FROM redact_tokens_v1.contexts WHERE tenant='synthetic-foreign-role-fixture'; "
               f'DROP OWNED BY {reader}; DROP ROLE {reader},{bridge_a},{bridge_b}; '
               'ALTER ROLE token_runtime INHERIT')
