#!/usr/bin/env python3
"""Open-loop texts[] load against a gateway this process starts.

Arrivals are scheduled on a clock. A request does not wait for the previous
one to finish before the next arrival is due. Prints statuses, counts, and
durations. Response bodies and vault tokens are not written.

Samples are these runs, not population percentiles, and not an approved SLO.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BENCH_KEY = "synthetic-openloop-key"
HEADER = {
    "queue_ms": "x-censgate-redact-queue-ms",
    "ner_ms": "x-censgate-redact-ner-ms",
    "onnx_ms": "x-censgate-redact-onnx-ms",
    "onnx_rounds": "x-censgate-redact-onnx-rounds",
    "vault_ms": "x-censgate-redact-vault-ms",
    "leaves": "x-censgate-redact-leaves",
    "bytes": "x-censgate-redact-bytes",
    "tokens": "x-censgate-redact-tokens",
}
STATIC = {
    "redact batch overloaded",
    "redact session map full",
    "dependency unavailable: redact batch deadline exceeded",
    "dependency unavailable: token map write failed",
    "dependency unavailable: token map read failed",
}


def classify(status, payload):
    if status is None:
        return "cancel_or_client_timeout"
    err = payload.get("error") or {} if isinstance(payload, dict) else {}
    kind = err.get("type") or ""
    message = err.get("message") or ""
    if status == 200:
        return "ok"
    if kind == "session_map_full" or status == 409:
        return "session_map_full"
    if kind == "overload":
        return "overload"
    if "deadline exceeded" in message:
        return "deadline"
    if kind == "invalid_request_error" or status == 400:
        return "invalid_request"
    if kind == "dependency_unavailable":
        return "dependency"
    if status >= 500:
        return "internal"
    return "other"


def stage_from(headers):
    out = {}
    for key, name in HEADER.items():
        raw = headers.get(name) if headers else None
        out[key] = int(raw) if raw and str(raw).isdigit() else None
    return out


def call(base, path, body, timeout, method="POST"):
    raw = json.dumps(body).encode()
    req = urllib.request.Request(
        base + path,
        data=raw,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + BENCH_KEY,
        },
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.load(response)
            return {
                "status": response.status,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "category": classify(response.status, payload),
                "stage": stage_from(response.headers),
                "payload": payload,
            }
    except urllib.error.HTTPError as err:
        try:
            payload = json.load(err)
        except Exception:
            payload = {}
        message = (payload.get("error") or {}).get("message") if isinstance(payload, dict) else None
        return {
            "status": err.code,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "category": classify(err.code, payload),
            "stage": stage_from(err.headers),
            "message": message if message in STATIC else None,
            "payload": payload if isinstance(payload, dict) else {},
        }
    except Exception:
        return {
            "status": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "category": "cancel_or_client_timeout",
            "stage": {},
            "payload": {},
        }


def outputs(result):
    payload = result.get("payload") or {}
    if payload.get("texts") is not None:
        return payload["texts"]
    if payload.get("text") is not None:
        return [payload["text"]]
    return []


def public(result):
    row = {
        "status": result.get("status"),
        "elapsed_ms": result.get("elapsed_ms"),
        "category": result.get("category"),
        "message": result.get("message"),
    }
    row.update(result.get("stage") or {})
    return row


def leaf(i, tag):
    return f'synthetic record {i}: {tag}{i}@example.test; quoted "雪"\n'


def long_leaf(i):
    pad = "synthetic-padding " * 16
    email = f"longfixture{i}@example.test"
    if i % 3 == 0:
        return email + " " + pad + "雪\n"
    if i % 3 == 1:
        return pad + " " + email + "\n"
    return "雪 " + pad[:40] + " " + email + " " + pad[40:] + "\n"


def parity_fixtures():
    email = "ada.one@example.test"
    return [
        f"Ada <{email}> wrote.",
        f"reach {email} today",
        f"note: {email}",
        "雪 ada.two@example.test",
        "person 雪 lives in 東京",
        ("A" * 200) + " ada.three@example.test",
        "ada.four@example.test " + ("B" * 200),
        "mid " + ("C" * 80) + " ada.five@example.test " + ("D" * 80),
        "",
        " ",
        "already [EMAIL_ADDRESS_99] stays",
        'quote "ada.six@example.test"\n雪\\',
    ]


class Gateway:
    def __init__(self, binary, env, cgroup):
        self.binary = binary
        self.env = env
        self.cgroup = cgroup
        self.proc = None
        self.base = None

    def start(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        log_path = Path("/tmp/redact-bench/openloop-gateway.log")
        self.log = log_path.open("a")
        self.proc = subprocess.Popen(
            [str(self.binary), "--host", "127.0.0.1", "--port", str(port)],
            env=self.env,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        if self.cgroup:
            subprocess.run(
                ["sudo", "tee", self.cgroup.rstrip("/") + "/cgroup.procs"],
                input=f"{self.proc.pid}\n".encode(),
                stdout=subprocess.DEVNULL,
                check=True,
            )
        for _ in range(240):
            if self.proc.poll() is not None:
                raise RuntimeError("gateway exited during startup")
            try:
                with urllib.request.urlopen(self.base + "/healthz", timeout=2) as response:
                    if response.status != 200:
                        raise RuntimeError("health")
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("gateway startup timed out")
        request = urllib.request.Request(
            self.base + "/v1/compliance/status",
            headers={"Authorization": "Bearer " + BENCH_KEY},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)
        log = getattr(self, "log", None)
        if log:
            log.close()

    def cgroup_stat(self):
        if not self.cgroup:
            return None
        root = Path(self.cgroup)
        out = {}
        for key in ("memory.current", "memory.peak", "memory.max", "cpu.max"):
            file = root / key
            if file.is_file():
                out[key] = file.read_text().strip()
        return out


def base_env():
    env = os.environ.copy()
    prefix = "synthetic-openloop-" + uuid.uuid4().hex
    env.update(
        CENSGATE_CONFIG_SOURCE="env",
        CENSGATE_NER_REQUIRED="true",
        CENSGATE_VAULT_BACKEND="vault_kv2",
        CENSGATE_VAULT_ADDR=env["REDACT_BENCH_VAULT_ADDR"],
        CENSGATE_VAULT_TOKEN=env["REDACT_BENCH_VAULT_TOKEN"],
        CENSGATE_VAULT_AUTH="token",
        CENSGATE_VAULT_MOUNT=env["REDACT_BENCH_VAULT_MOUNT"],
        CENSGATE_VAULT_PATH_PREFIX=prefix,
        CENSGATE_AUTH_MODE="api_key",
        CENSGATE_API_KEYS=BENCH_KEY,
        CENSGATE_REDACT_BATCH_ENABLED="true",
        CENSGATE_NER_INTRA_THREADS="1",
        CENSGATE_NER_SESSION_POOL="1",
        CENSGATE_REDACT_BATCH_INFLIGHT="1",
        CENSGATE_REDACT_BATCH_QUEUE_MS="15000",
        CENSGATE_REDACT_BATCH_QUEUE_DEPTH="2",
        OTEL_SDK_DISABLED="true",
    )
    for key in ("CENSGATE_VAULT_NAMESPACE", "CENSGATE_POLICY_FILE", "CENSGATE_DEFAULT_PROFILE"):
        env.pop(key, None)
    return env


def open_loop(jobs):
    """jobs are (delay_seconds, fn). Each fn runs at that offset from t0."""
    results = [None] * len(jobs)
    errors = []
    start = time.perf_counter()

    def run(index, delay, fn):
        try:
            remaining = delay - (time.perf_counter() - start)
            if remaining > 0:
                time.sleep(remaining)
            results[index] = fn()
        except Exception as err:
            errors.append(str(err))

    threads = [
        threading.Thread(target=run, args=(i, delay, fn))
        for i, (delay, fn) in enumerate(jobs)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise RuntimeError(errors[0])
    return results


def redact(base, texts, session, timeout):
    return call(
        base,
        "/v1/redact",
        {"texts": texts, "profile": "reversible", "session_id": session},
        timeout,
    )


def one_shot(binary, cgroup, env_extra, texts, session):
    env = base_env()
    env.update(env_extra)
    gateway = Gateway(binary, env, cgroup)
    try:
        gateway.start()
        result = redact(gateway.base, texts, session, 60)
        return public(result)
    finally:
        gateway.stop()


def main():
    vault = os.environ.get("REDACT_BENCH_VAULT_ADDR", "")
    if urllib.parse.urlparse(vault).hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing non-local vault endpoint")
    binary = Path(os.environ.get("REDACT_BENCH_GATEWAY", "target/release/redact-gateway")).resolve()
    out_path = Path(
        os.environ.get(
            "REDACT_BENCH_OUTPUT",
            "/opt/cursor/artifacts/redaction-batching-openloop.json",
        )
    )
    cgroup = os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", "/sys/fs/cgroup/redact-gw")
    result = {
        "note": "Single-run open-loop samples on one CPU. Not population percentiles and not an approved SLO.",
        "intra_threads": 1,
        "session_pool": 1,
        "inflight": 1,
        "queue_ms": 15000,
        "queue_depth": 2,
        "spin_default": "off",
        "optimization": "Level3 (includes Level2 attention fusion)",
    }
    if os.environ.get("REDACT_OPENLOOP_AB") == "1":
        short = [leaf(i, "ab") for i in range(64)]
        longer = [long_leaf(i) for i in range(32)]
        result["thread_ab"] = {
            "short64_spin_off": one_shot(binary, cgroup, {}, short, "ab-short-off"),
            "short64_spin_on": one_shot(
                binary, cgroup, {"CENSGATE_NER_INTRA_SPIN": "1"}, short, "ab-short-on"
            ),
            "long32_spin_off": one_shot(binary, cgroup, {}, longer, "ab-long-off"),
            "long32_spin_on": one_shot(
                binary, cgroup, {"CENSGATE_NER_INTRA_SPIN": "1"}, longer, "ab-long-on"
            ),
            "long32_opt_all": one_shot(
                binary, cgroup, {"CENSGATE_NER_OPT_LEVEL": "all"}, longer, "ab-long-all"
            ),
        }
        print(json.dumps(result["thread_ab"]), flush=True)
        if os.environ.get("REDACT_OPENLOOP_AB_ONLY") == "1":
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(result, indent=2) + "\n")
            return

    env = base_env()
    gateway = Gateway(binary, env, cgroup)
    try:
        status = gateway.start()
        caps = status.get("capabilities") or {}
        result["advertised"] = {
            key: caps.get(key)
            for key in (
                "redact_texts_v1",
                "max_texts",
                "max_text_bytes",
                "max_total_bytes",
                "timeout_ms",
            )
        }
        result["backend"] = status.get("token_map_backend")
        result["cgroup_at_start"] = gateway.cgroup_stat()
        fixtures = parity_fixtures()
        serial = []
        for text in fixtures:
            one = call(
                gateway.base,
                "/v1/redact",
                {"text": text, "profile": "reversible", "session_id": "parity-serial"},
                60,
            )
            serial.extend(outputs(one))
        batched = redact(gateway.base, fixtures, "parity-batch", 60)
        batch_out = outputs(batched)
        emails = [
            "ada.one@example.test",
            "ada.two@example.test",
            "ada.three@example.test",
            "ada.four@example.test",
            "ada.five@example.test",
            "ada.six@example.test",
        ]
        result["parity"] = {
            "leaves": len(fixtures),
            "equal": serial == batch_out and len(serial) == len(fixtures),
            "batch_category": batched["category"],
            "batch_stage": batched.get("stage"),
            "raw_email_survived": any(email in text for email in emails for text in batch_out),
            "unicode_kept": any("雪" in text for text in batch_out),
            "empty_kept": batch_out[8:10] == ["", " "] if len(batch_out) >= 10 else False,
        }
        print(json.dumps({"parity": result["parity"]}), flush=True)
        if not result["parity"]["equal"] or result["parity"]["raw_email_survived"]:
            raise SystemExit("parity failed")

        def short800():
            return redact(gateway.base, [leaf(i, "open") for i in range(800)], "open-short", 45)

        def tenant139():
            return redact(gateway.base, [leaf(i, "other") for i in range(139)], "open-other", 45)

        burst = open_loop([(0, short800), (0, tenant139)])
        result["open_loop_t0"] = [public(item) for item in burst]
        short_out = outputs(burst[0])
        result["open_loop_t0_raw_email_survived"] = any("example.test" in text for text in short_out)
        print(json.dumps({"open_loop_t0": result["open_loop_t0"]}), flush=True)

        longer = redact(gateway.base, [long_leaf(i) for i in range(800)], "open-long", 45)
        result["long_800"] = public(longer)
        result["long_800"]["leaf_bytes"] = len(long_leaf(1).encode())
        long_out = outputs(longer)
        result["long_800"]["raw_email_survived"] = any("example.test" in text for text in long_out)
        print(json.dumps({"long_800": result["long_800"]}), flush=True)

        mixed_leaves = [leaf(i, "mix") if i % 2 == 0 else long_leaf(i) for i in range(800)]
        mixed = redact(gateway.base, mixed_leaves, "open-mixed", 45)
        result["mixed_800"] = public(mixed)
        mixed_out = outputs(mixed)
        result["mixed_800"]["raw_email_survived"] = any("example.test" in text for text in mixed_out)
        print(json.dumps({"mixed_800": result["mixed_800"]}), flush=True)

        def tenant(name):
            return redact(gateway.base, [leaf(i, name) for i in range(139)], name, 60)

        queued = open_loop([(0, lambda: tenant("tenant-a")), (0, lambda: tenant("tenant-b"))])
        result["concurrent_tenants_139"] = [public(item) for item in queued]
        print(json.dumps({"concurrent_tenants_139": result["concurrent_tenants_139"]}), flush=True)
        result["cgroup_after"] = gateway.cgroup_stat()
    finally:
        gateway.stop()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"done": True, "output": str(out_path)}), flush=True)


if __name__ == "__main__":
    main()
