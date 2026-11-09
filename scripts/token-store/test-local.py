#!/usr/bin/env python3
"""Run synthetic backend contract tests with caller-supplied local binaries."""
import os, pathlib, re, socket, subprocess, tempfile, time, json

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)

def unused_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]

def verify_postgres(process, psql, expected_directory):
    # This read-only identity check must precede every setup mutation.
    if process.poll() is not None:
        raise RuntimeError('local PostgreSQL child is not running')
    actual = run(psql + ['-At', '-c', 'SHOW data_directory'], capture_output=True, text=True).stdout.strip()
    if pathlib.Path(actual).resolve() != expected_directory.resolve():
        raise RuntimeError('PostgreSQL endpoint is not the throwaway instance')
    pid = int((expected_directory/'postmaster.pid').read_text().splitlines()[0])
    if pid != process.pid or process.poll() is not None:
        raise RuntimeError('PostgreSQL instance does not belong to this harness')

def ready(process, port):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError('local dependency exited before readiness')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                if process.poll() is not None:
                    raise RuntimeError('local dependency exited during readiness')
                return
        except OSError: time.sleep(.1)
    raise RuntimeError('local dependency did not become ready')

def main():
    from preflight_contract import exercise as preflight_contract
    root = pathlib.Path(__file__).resolve().parents[2]
    pgbin = pathlib.Path(os.environ['TOKEN_STORE_PG_BIN'])
    pgshare = os.environ['TOKEN_STORE_PG_SHARE']
    baobin = os.environ['TOKEN_STORE_BAO_BIN']
    processes = []
    with tempfile.TemporaryDirectory(prefix='token-store-contract-') as work:
        work = pathlib.Path(work)
        try:
            run([str(pgbin/'initdb'), '-D', str(work/'pg'), '-L', pgshare, '--auth=trust', '--encoding=UTF8', '--no-locale'], stdout=subprocess.DEVNULL)
            pglog = open(work/'postgres.log', 'w')
            pgport = unused_port()
            processes.append(subprocess.Popen([str(pgbin/'postgres'), '-D', str(work/'pg'), '-p', str(pgport), '-h', '127.0.0.1', '-c', 'unix_socket_directories='], stdout=pglog, stderr=pglog))
            ready(processes[0], pgport)
            psql = [str(pgbin/'psql'), '-h', '127.0.0.1', '-p', str(pgport), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
            verify_postgres(processes[0], psql, work/'pg')
            run(psql + ['-f', str(root/'crates/redact-token-store/src/schema.sql')], stdout=subprocess.DEVNULL)
            verify_postgres(processes[0], psql, work/'pg')
            run(psql + ['-c', 'CREATE ROLE token_runtime LOGIN NOSUPERUSER NOBYPASSRLS; GRANT USAGE ON SCHEMA redact_tokens_v1 TO token_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON redact_tokens_v1.contexts,redact_tokens_v1.entries,redact_tokens_v1.aliases TO token_runtime;'], stdout=subprocess.DEVNULL)
            verify_postgres(processes[0], psql, work/'pg')
            run(psql + ['-c', 'CREATE DATABASE token_shard_fixture'], stdout=subprocess.DEVNULL)
            shard_psql = psql + ['-d', 'token_shard_fixture']
            verify_postgres(processes[0], shard_psql, work/'pg')
            run(shard_psql + ['-f', str(root/'crates/redact-token-store/src/schema.sql')], stdout=subprocess.DEVNULL)
            for connection in [psql, shard_psql]:
                verify_postgres(processes[0], connection, work/'pg')
                run(connection + ['-c', "GRANT USAGE ON SCHEMA redact_tokens_v1 TO token_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON redact_tokens_v1.contexts,redact_tokens_v1.entries,redact_tokens_v1.aliases TO token_runtime; GRANT SELECT ON redact_tokens_v1.configuration TO token_runtime; INSERT INTO redact_tokens_v1.configuration VALUES(true, repeat('a',64), 'synthetic-shard');"], stdout=subprocess.DEVNULL)
            baolog = open(work/'openbao.log', 'w')
            baoport = unused_port()
            baoargs = [baobin, 'server', '-dev', f'-dev-listen-address=127.0.0.1:{baoport}']
            if os.environ.get('TOKEN_STORE_BAO_JSON_STRINGS'):
                baoport = unused_port()
                config = work/'bao.json'
                config.write_text(json.dumps({'listener': [{'tcp': {'address':f'127.0.0.1:{baoport}', 'tls_disable': True, 'max_request_json_strings':int(os.environ['TOKEN_STORE_BAO_JSON_STRINGS'])}}]}))
                baoargs += ['-config', str(config)]
            processes.append(subprocess.Popen(baoargs, stdout=baolog, stderr=baolog))
            ready(processes[1], baoport)
            for _ in range(100):
                token = re.search(r'Root Token: (\S+)', (work/'openbao.log').read_text())
                if token: break
                time.sleep(.1)
            if not token: raise RuntimeError('local OpenBao credential unavailable')
            tokenfile = work/'token'
            tokenfile.write_text(token.group(1))
            tokenfile.chmod(0o600)
            env = dict(os.environ, OTEL_SDK_DISABLED='true', TOKEN_STORE_PG_URL=f'postgres://token_runtime@127.0.0.1:{pgport}/postgres', TOKEN_STORE_PG_URL_2=f'postgres://token_runtime@127.0.0.1:{pgport}/token_shard_fixture', TOKEN_STORE_BAO_ADDR=f'http://127.0.0.1:{baoport}', TOKEN_STORE_BAO_TOKEN_FILE=str(tokenfile))
            def fixture_sql(index, statement):
                connection = [psql, shard_psql][index]
                verify_postgres(processes[0], connection, work/'pg')
                return run(connection + ['-At', '-c', statement], capture_output=True, text=True).stdout
            preflight_contract(root, work, env, fixture_sql)
            run(['cargo', 'test', '-p', 'redact-token-store', '--', '--include-ignored', '--nocapture'], cwd=root, env=env)
            run(['cargo', 'test', '-p', 'redact-gateway', '--test', 'indexed_tokens', '--', '--include-ignored', '--nocapture'], cwd=root, env=env)
            if os.environ.get('TOKEN_STORE_RUN_BETA_ACCEPTANCE') == '1':
                from beta_acceptance import exercise as beta_acceptance
                beta_acceptance(root, work, env, fixture_sql)
            if os.environ.get('TOKEN_STORE_RUN_BENCH') == '1':
                outdir = pathlib.Path(os.environ['TOKEN_STORE_BENCH_OUTPUT'])
                outdir.mkdir(parents=True, exist_ok=True)
                children = []
                for worker in range(2):
                    output = open(outdir/f'worker-{worker}.csv', 'w')
                    children.append(subprocess.Popen([str(root/'target/release/examples/compare')], cwd=root, env=dict(env, TOKEN_STORE_BENCH_WORKER=str(worker)), stdout=output))
                for child in children:
                    if child.wait() != 0: raise RuntimeError('benchmark worker failed')
                print('Saved two-process benchmark output to', outdir)
        finally:
            for process in processes: process.terminate()
            for process in processes:
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()

if __name__ == "__main__":
    main()
