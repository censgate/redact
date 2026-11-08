"""Two real gateway processes, synthetic traffic, and a bounded local OTLP sink.

Only invoked inside test-local.py's verified throwaway dependency lifecycle.
No URL/credential CLI, live target support, response logging, or cloud operations.
"""
import base64
import concurrent.futures
from collections import Counter
import hashlib
import http.server
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid


def owns_listener(child, port):
    """Linux-only proof that this child owns the loopback listening socket."""
    if child.poll() is not None:
        return False
    sockets = set()
    for fd in Path(f'/proc/{child.pid}/fd').iterdir():
        try:
            sockets.add(os.readlink(fd))
        except FileNotFoundError:
            pass
    for row in Path(f'/proc/{child.pid}/net/tcp').read_text().splitlines()[1:]:
        fields = row.split()
        if (fields[1] == f'0100007F:{port:04X}' and fields[3] == '0A'
                and f'socket:[{fields[9]}]' in sockets):
            return child.poll() is None
    return False


def exercise(root, work, env, sql):
    processes, logs, secrets, contexts = [], [], [], []
    captured, capture_lock = [], threading.Lock()
    capture_bytes = 0
    capture_overflow = False
    rejected = Counter()

    class Sink(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            nonlocal capture_bytes, capture_overflow
            size = int(self.headers.get('Content-Length', '0'))
            if self.path not in ['/v1/traces', '/v1/metrics'] or not 0 < size <= 4 * 1024 * 1024:
                rejected['path' if self.path not in ['/v1/traces', '/v1/metrics'] else 'size'] += 1
                self.send_error(413)
                return
            body = self.rfile.read(size)
            with capture_lock:
                capture_bytes += len(body)
                if capture_bytes <= 64 * 1024 * 1024:
                    captured.append((self.path, body))
                else:
                    capture_overflow = True
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-protobuf')
            self.send_header('Content-Length', '0')
            self.end_headers()

    sink = http.server.HTTPServer(('127.0.0.1', 0), Sink)
    sink.timeout = 2
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    key = base64.b64encode(os.urandom(32)).decode()
    owners = [uuid.uuid4().hex for _ in range(2)]
    secrets.extend([key, *owners, (work / 'token').read_text().strip()])
    keyfile = work / 'beta-root-key'
    keyfile.write_text(key)
    keyfile.chmod(0o600)
    clean = {k: v for k, v in env.items() if not k.startswith(
        ('CENSGATE_', 'VAULT_', 'BAO_', 'OTEL_')) and k.lower() not in
        ['http_proxy', 'https_proxy', 'all_proxy']}
    clean.update(CENSGATE_TOKEN_DEK=key,
                 CENSGATE_API_KEYS=','.join(owners),
                 CENSGATE_VAULT_TOKEN=secrets[-1], CENSGATE_DEFAULT_PROFILE='reversible',
                 TOKEN_STORE_ROOT_KEY_FILE=str(keyfile), OTEL_SDK_DISABLED='false',
                 OTEL_TRACES_EXPORTER='otlp', OTEL_METRICS_EXPORTER='otlp',
                 OTEL_LOGS_EXPORTER='none', OTEL_TRACES_SAMPLER='always_on',
                 OTEL_PROPAGATORS='tracecontext', OTEL_BSP_SCHEDULE_DELAY='100',
                 OTEL_METRIC_EXPORT_INTERVAL='200',
                 OTEL_EXPORTER_OTLP_PROTOCOL='http/protobuf',
                 OTEL_EXPORTER_OTLP_ENDPOINT=f'http://127.0.0.1:{sink.server_port}',
                 OTEL_SERVICE_NAME='synthetic-token-store-acceptance', RUST_LOG='info')
    routing = [['fixture-one', 'fixture-two'], [n % 2 for n in range(256)]]
    commitment = subprocess.run(
        ['cargo', 'run', '--quiet', '-p', 'redact-token-store', '--example', 'configuration'],
        cwd=root, env=clean, input=json.dumps(routing), text=True,
        capture_output=True, check=True).stdout.strip()
    assert re.fullmatch('[0-9a-f]{64}', commitment), 'invalid generation commitment'
    config = {'auth': {'mode': 'api_key'}, 'ner': {'required': False},
              'provider': {'base_url': 'http://127.0.0.1:1'},
              'telemetry': {'operations': 'basic', 'filter': 'info', 'genai_attributes': False},
              'vault': {'backend': 'vault_kv2', 'address': env['TOKEN_STORE_BAO_ADDR'],
                        'path_prefix': 'synthetic-beta-' + uuid.uuid4().hex, 'ttl_secs': 3600}}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(peer, path, body=None, owner=0, method=None):
        process, port = peer
        assert process.poll() is None, 'gateway child is not running'
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=data,
                                     headers={'Authorization': 'Bearer ' + owners[owner],
                                              'Content-Type': 'application/json'}, method=method)
        try:
            response = opener.open(req, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read(1024 * 1024 + 1)
            assert len(payload) <= 1024 * 1024, 'response exceeded fixture budget'
            return response.status, json.loads(payload)

    def stop(peer):
        child = peer[0]
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise AssertionError('gateway failed to drain before deadline') from None
        assert child.returncode == 0, 'gateway child failed'

    def launch(index):
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        path = work / f'beta-gateway-{len(logs)}.log'
        logs.append(path)
        configfile = work / f'beta-config-{len(logs)}.json'
        configfile.write_text(json.dumps(config))
        with path.open('wb') as output:
            child = subprocess.Popen([str(root / 'target/debug/redact-gateway'),
                                      '--config', str(configfile), '--host', '127.0.0.1',
                                      '--port', str(port)], cwd=root,
                                     env=dict(clean, OTEL_RESOURCE_ATTRIBUTES=f'service.instance.id=synthetic-peer-{index}'),
                                     stdout=output, stderr=output)
        processes.append(child)
        peer = (child, port)
        for _ in range(300):
            assert child.poll() is None, 'gateway exited before readiness'
            # Verify the listening inode belongs to the child before any HTTP
            # traffic; an unrelated local listener cannot authorize writes.
            if owns_listener(child, port):
                status, _ = request(peer, '/readyz')
                if status == 200:
                    return peer
            time.sleep(.1)
        raise AssertionError('gateway readiness timed out')

    def context():
        value = 'synthetic-context-' + uuid.uuid4().hex
        contexts.append(value)
        return value

    def red(peer, ctx, value):
        return request(peer, '/v1/redact', {'text': value, 'session_id': ctx})

    def restore(peer, ctx, text, owner=0):
        return request(peer, '/v1/restore', {'text': text, 'session_id': ctx}, owner)

    results = []
    try:
        for index, name in enumerate(routing[0]):
            sql(index, f"UPDATE redact_tokens_v1.configuration SET commitment='{commitment}',shard_id='{name}'")
        legacy = launch('legacy')
        migrated = context()
        original = 'migration-canary@fixture.invalid'
        status, response = red(legacy, migrated, original)
        assert status == 200 and response['text'] != original, 'legacy seeding failed'
        legacy_label = response['text']
        stop(legacy)  # Actual local writer barrier before enabling the target.
        config['vault']['indexed'] = {'shard_ids': routing[0],
                                     'connection_env': ['TOKEN_STORE_PG_URL', 'TOKEN_STORE_PG_URL_2'],
                                     'ownership': routing[1], 'legacy_writers_drained': True}
        peers = [launch(0), launch(1)]
        for peer in peers:
            status, response = restore(peer, migrated, legacy_label)
            assert status == 200 and response['text'] == original, 'migration identity mismatch'
        status, response = restore(peers[1], migrated, legacy_label, owner=1)
        assert status == 200 and response['text'] == legacy_label, 'foreign principal restored a value'

        # Concurrent first allocation/retry must converge across independent processes.
        concurrent_ctx = context()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            allocations = list(executor.map(lambda n: red(peers[n % 2], concurrent_ctx, original), range(32)))
        assert all(s == 200 for s, _ in allocations), 'concurrent allocation HTTP counts: ' + str(Counter(s for s, _ in allocations))
        assert len({v['text'] for _, v in allocations}) == 1, 'peer allocation rebound identity'
        stable = allocations[0][1]['text']
        stop(peers[1])
        peers[1] = launch(1)
        assert restore(peers[1], concurrent_ctx, stable)[1]['text'] == original, 'restart lost identity'

        sizes = [int(x) for x in os.environ.get('TOKEN_STORE_BETA_SIZES', '10,1000').split(',')]
        assert sizes and len(sizes) <= 3 and all(x in [10, 1000, 10000] for x in sizes), 'invalid fixture sizes'
        for size in sizes:
            ctx = context()
            first = 'person00000@fixture.invalid'
            first_label = None
            for start in range(0, size, 100):
                values = [f'person{n:05d}@fixture.invalid' for n in range(start, min(start + 100, size))]
                status, response = red(peers[(start // 100) % 2], ctx, ' '.join(values))
                token_count = len(re.findall(r'\[EMAIL_ADDRESS_[0-9]+\]', response.get('text', '')))
                assert status == 200 and '@fixture.invalid' not in response['text'], (
                    f'context seeding failed: size={size}, offset={start}, status={status}, blocked={response.get("blocked")}, '
                    f'remaining={sum(v in response.get("text", "") for v in values)}, '
                    f'tokens={token_count}')
                assert token_count == len(values), 'fixture mapping count differs from requested context growth'
                if first_label is None:
                    first_label = response['text'].split()[0]
            for concurrency in [1, 8, 32]:
                for operation in ['resolve', 'reuse']:
                    def sample(n):
                        started = time.perf_counter()
                        status, response = (restore(peers[n % 2], ctx, ' '.join([first_label] * 8))
                                            if operation == 'resolve' else red(peers[n % 2], ctx, first))
                        elapsed = (time.perf_counter() - started) * 1000
                        expected = ' '.join([first] * 8) if operation == 'resolve' else first_label
                        assert status == 200 and response['text'] == expected, 'load response invariant failed'
                        return elapsed
                    started = time.perf_counter()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                        times = sorted(executor.map(sample, range(96)))
                    seconds = time.perf_counter() - started
                    results.append({'context_mappings': size, 'concurrency': concurrency,
                                    'operation': operation, 'requests': len(times), 'errors': 0,
                                    'p50_ms': round(times[math.ceil(.5 * len(times)) - 1], 3),
                                    'p95_ms': round(times[math.ceil(.95 * len(times)) - 1], 3),
                                    'p99_ms': round(times[math.ceil(.99 * len(times)) - 1], 3),
                                    'requests_per_second': round(len(times) / seconds, 2)})

        # Logical database outage only, inside this verified disposable cluster.
        sql(0, 'ALTER DATABASE token_shard_fixture ALLOW_CONNECTIONS false; '
               "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='token_shard_fixture'")
        try:
            assert all(request(peer, '/readyz')[0] == 503 for peer in peers), 'unavailable shard stayed ready'
        finally:
            sql(0, 'ALTER DATABASE token_shard_fixture ALLOW_CONNECTIONS true')
        for peer in peers:
            for _ in range(30):
                if request(peer, '/readyz')[0] == 200:
                    break
                time.sleep(.2)
            else:
                raise AssertionError('shard recovery failed')
            assert restore(peer, migrated, legacy_label)[1]['text'] == original, 'recovery lost identity'
        status, _ = request(peers[0], '/v1/vault/context', {'vault': {'context_id': concurrent_ctx}}, method='DELETE')
        assert status == 200, 'erasure failed'
        assert restore(peers[1], concurrent_ctx, stable)[1]['text'] == stable, 'erased token restored'
        assert red(peers[1], concurrent_ctx, original)[0] == 410, 'retired identity rebound'
        for peer in peers:
            stop(peer)
        assert not capture_overflow, 'OTLP capture budget exceeded'
        traces = b''.join(body for path, body in captured if path == '/v1/traces')
        metrics = b''.join(body for path, body in captured if path == '/v1/metrics')
        missing = [marker.decode() for marker in [b'intern', b'resolve', b'postgres_sharded',
                                                  b'synthetic-peer-0', b'synthetic-peer-1'] if marker not in traces]
        assert not missing, ('operation trace markers missing: ' + ','.join(missing) +
                             f'; trace_bytes={len(traces)}, metric_bytes={len(metrics)}, rejects={dict(rejected)}')
        assert b'http.server.request.duration' in metrics, 'HTTP metric export missing'
        output = traces + metrics + b''.join(path.read_bytes() for path in logs)
        assert all(value.encode() not in output for value in [*secrets, *contexts, '@fixture.invalid',
                                                               '[EMAIL_ADDRESS_']), 'sensitive fixture data entered telemetry/logs'
        summary = {'fixture': 'two-process-loopback-debug-regex-only', 'replicas': 2,
                   'logical_databases': 2, 'postgres_servers': 1, 'ner_enabled': False,
                   'postgres_version': sql(0, 'SHOW server_version').strip(),
                   'source_sha256': {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in [
                       'scripts/token-store/beta_acceptance.py', 'Cargo.lock',
                       'crates/redact-gateway/Cargo.toml',
                       'crates/redact-core/src/recognizers/pattern.rs',
                       'crates/redact-gateway/src/vault/indexed.rs',
                       'crates/redact-gateway/src/vault/kv2.rs']},
                   'checks': ['legacy-drain', 'identity-import', 'foreign-principal', 'concurrent-reuse',
                              'process-restart', 'logical-shard-outage-recovery', 'retire-no-rebind',
                              'otlp-http-traces-metrics', 'telemetry-canary-exclusion'],
                   'otlp_requests': len(captured), 'otlp_bytes': capture_bytes, 'load': results}
        print('Synthetic two-process acceptance: ' + json.dumps(summary, sort_keys=True))
        if os.environ.get('TOKEN_STORE_BETA_OUTPUT'):
            with open(os.environ['TOKEN_STORE_BETA_OUTPUT'], 'w') as report:
                json.dump(summary, report, indent=2)
                report.write('\n')
    finally:
        for child in processes:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=3)
        for index in range(2):
            sql(index, "UPDATE redact_tokens_v1.configuration SET commitment=repeat('a',64),shard_id='synthetic-shard'")
