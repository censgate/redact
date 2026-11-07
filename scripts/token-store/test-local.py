#!/usr/bin/env python3
"""Run synthetic backend contract tests with caller-supplied local binaries."""
import os, pathlib, re, socket, subprocess, tempfile, time, json
root = pathlib.Path(__file__).resolve().parents[2]
pgbin = pathlib.Path(os.environ['TOKEN_STORE_PG_BIN'])
pgshare = os.environ['TOKEN_STORE_PG_SHARE']
baobin = os.environ['TOKEN_STORE_BAO_BIN']
processes = []

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)

def ready(port):
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1): return
        except OSError: time.sleep(.1)
    raise RuntimeError('local dependency did not become ready')

with tempfile.TemporaryDirectory(prefix='token-store-contract-') as work:
    work = pathlib.Path(work)
    try:
        run([str(pgbin/'initdb'), '-D', str(work/'pg'), '-L', pgshare, '--auth=trust', '--encoding=UTF8', '--no-locale'], stdout=subprocess.DEVNULL)
        pglog = open(work/'postgres.log', 'w')
        processes.append(subprocess.Popen([str(pgbin/'postgres'), '-D', str(work/'pg'), '-p', '15432', '-h', '127.0.0.1', '-c', 'unix_socket_directories='], stdout=pglog, stderr=pglog))
        ready(15432)
        psql = [str(pgbin/'psql'), '-h', '127.0.0.1', '-p', '15432', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
        run(psql + ['-f', str(root/'crates/redact-token-store/src/schema.sql')], stdout=subprocess.DEVNULL)
        run(psql + ['-c', 'CREATE ROLE token_runtime LOGIN NOSUPERUSER NOBYPASSRLS; GRANT USAGE ON SCHEMA redact_tokens_v1 TO token_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON redact_tokens_v1.contexts,redact_tokens_v1.entries TO token_runtime;'], stdout=subprocess.DEVNULL)
        baolog = open(work/'openbao.log', 'w')
        baoargs = [baobin, 'server', '-dev', '-dev-listen-address=127.0.0.1:18200']
        baoport = 18200
        if os.environ.get('TOKEN_STORE_BAO_JSON_STRINGS'):
            baoport = 18210
            config = work/'bao.json'
            config.write_text(json.dumps({'listener': [{'tcp': {'address':'127.0.0.1:18210', 'tls_disable': True, 'max_request_json_strings':int(os.environ['TOKEN_STORE_BAO_JSON_STRINGS'])}}]}))
            baoargs += ['-config', str(config)]
        processes.append(subprocess.Popen(baoargs, stdout=baolog, stderr=baolog))
        ready(baoport)
        for _ in range(100):
            token = re.search(r'Root Token: (\S+)', (work/'openbao.log').read_text())
            if token: break
            time.sleep(.1)
        if not token: raise RuntimeError('local OpenBao credential unavailable')
        tokenfile = work/'token'
        tokenfile.write_text(token.group(1))
        tokenfile.chmod(0o600)
        env = dict(os.environ, TOKEN_STORE_PG_URL='postgres://token_runtime@127.0.0.1:15432/postgres', TOKEN_STORE_BAO_ADDR=f'http://127.0.0.1:{baoport}', TOKEN_STORE_BAO_TOKEN_FILE=str(tokenfile))
        run(['cargo', 'test', '-p', 'redact-token-store', '--', '--include-ignored', '--nocapture'], cwd=root, env=env)
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
