"""Preflight regressions on the harness-owned databases; never a live target."""
import base64
import json
import os
import subprocess


def exercise(root, work, env, sql):
    # sql is the harness callback that verifies the child PID/data directory
    # before each administrative write. Credentials never enter argv or output.
    key = base64.b64encode(os.urandom(32)).decode()
    keyfile = work / 'preflight-key'
    keyfile.write_text(key)
    keyfile.chmod(0o600)
    clean_env = {k: v for k, v in env.items()
                 if not k.startswith(('CENSGATE_', 'VAULT_', 'BAO_'))}
    clean_env.update(CENSGATE_TOKEN_DEK=key,
                     CENSGATE_API_KEYS='synthetic-preflight-owner',
                     CENSGATE_VAULT_TOKEN=(work / 'token').read_text(),
                     TOKEN_STORE_ROOT_KEY_FILE=str(keyfile))
    routing = [['fixture-one', 'fixture-two'], [n % 2 for n in range(256)]]
    calculated = subprocess.run(
        ['cargo', 'run', '--quiet', '-p', 'redact-token-store', '--example', 'configuration'],
        cwd=root, env=clean_env, input=json.dumps(routing), text=True,
        capture_output=True, check=True).stdout.strip()
    assert len(calculated) == 64 and all(c in '0123456789abcdef' for c in calculated)
    subprocess.run(['cargo', 'build', '--quiet', '-p', 'redact-gateway'],
                   cwd=root, env=clean_env, check=True)
    config = {
        'auth': {'mode': 'api_key'},
        'ner': {'required': True, 'model_path': str(work / 'nonexistent-model')},
        'provider': {'base_url': 'http://127.0.0.1:1'},
        'vault': {'backend': 'vault_kv2', 'address': env['TOKEN_STORE_BAO_ADDR'],
                  'indexed': {'shard_ids': routing[0],
                              'connection_env': ['TOKEN_STORE_PG_URL', 'TOKEN_STORE_PG_URL_2'],
                              'ownership': routing[1], 'legacy_writers_drained': True}}}
    configfile = work / 'preflight.yaml'

    def check(expected, overlay=None):
        configfile.write_text(json.dumps(config))  # JSON is a YAML subset.
        result = subprocess.run(
            [str(root / 'target/debug/redact-gateway'), '--config', str(configfile),
             'check-token-store'], cwd=root, env=dict(clean_env, **(overlay or {})),
            capture_output=True, text=True, timeout=35)
        assert key not in result.stdout + result.stderr, 'preflight exposed key'
        if (result.returncode == 0) != expected:
            # Only allow content-free error categories into test diagnostics.
            categories = [line for line in result.stderr.splitlines()
                          if 'token-store ' in line or 'unknown field' in line]
            raise AssertionError('unexpected preflight outcome: ' + '; '.join(categories))
        if expected:
            assert 'postgres_sharded' in result.stdout, 'preflight did not select indexed store'

    for index, name in enumerate(routing[0]):
        sql(index, f"UPDATE redact_tokens_v1.configuration SET commitment='{calculated}',shard_id='{name}'")
    try:
        check(True)
        check(False, {'CENSGATE_TOKEN_DEK': base64.b64encode(os.urandom(32)).decode()})
        check(False, {'TOKEN_STORE_PG_URL_2': 'postgres://127.0.0.1:1/unavailable'})
        config['vault']['indexed']['ownership'][0] = 1
        check(False)
        config['vault']['indexed']['ownership'][0] = 0
        config['vault']['indexed']['legacy_writers_drained'] = False
        check(False)
        config['vault']['indexed']['legacy_writers_drained'] = True
        # Mutate only the second shard: one routed probe would miss these.
        cases = [
            ('ALTER TABLE redact_tokens_v1.entries DISABLE ROW LEVEL SECURITY',
             'ALTER TABLE redact_tokens_v1.entries ENABLE ROW LEVEL SECURITY'),
            ('ALTER TABLE redact_tokens_v1.entries NO FORCE ROW LEVEL SECURITY',
             'ALTER TABLE redact_tokens_v1.entries FORCE ROW LEVEL SECURITY'),
            ('CREATE POLICY unsafe_extra ON redact_tokens_v1.entries USING (true)',
             'DROP POLICY unsafe_extra ON redact_tokens_v1.entries'),
            ('GRANT CREATE ON SCHEMA redact_tokens_v1 TO token_runtime',
             'REVOKE CREATE ON SCHEMA redact_tokens_v1 FROM token_runtime'),
            ('GRANT SELECT ON redact_tokens_v1.entries_p0 TO token_runtime',
             'REVOKE SELECT ON redact_tokens_v1.entries_p0 FROM token_runtime'),
            ('GRANT UPDATE ON redact_tokens_v1.configuration TO token_runtime',
             'REVOKE UPDATE ON redact_tokens_v1.configuration FROM token_runtime'),
            ('GRANT UPDATE(commitment) ON redact_tokens_v1.configuration TO token_runtime',
             'REVOKE UPDATE(commitment) ON redact_tokens_v1.configuration FROM token_runtime'),
            ('GRANT SELECT(sealed) ON redact_tokens_v1.entries_p0 TO token_runtime',
             'REVOKE SELECT(sealed) ON redact_tokens_v1.entries_p0 FROM token_runtime'),
            ('GRANT TRUNCATE ON redact_tokens_v1.contexts TO token_runtime',
             'REVOKE TRUNCATE ON redact_tokens_v1.contexts FROM token_runtime'),
            ('REVOKE DELETE ON redact_tokens_v1.aliases FROM token_runtime',
             'GRANT DELETE ON redact_tokens_v1.aliases TO token_runtime'),
        ]
        for broken, repaired in cases:
            sql(1, broken)
            try:
                check(False)
            finally:
                sql(1, repaired)
        check(True)
        for index in range(2):
            assert sql(index, 'SELECT count(*) FROM redact_tokens_v1.contexts').strip() == '0', \
                'preflight created a context'
        print('Preflight: healthy, wrong key/map, unavailable second shard, drain gate, '
              '10 isolation/privilege failures, recovery and zero token mutations passed')
    finally:
        for index in range(2):
            sql(index, "UPDATE redact_tokens_v1.configuration SET commitment=repeat('a',64),shard_id='synthetic-shard'")
