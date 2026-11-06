#!/usr/bin/env python3
"""Session-map spill, parity, and scaling probe.

Talks only to a gateway this process starts and to a local KV. Prints statuses,
counts, and durations. Response bodies and vault tokens are not written.
Samples are the runs themselves, not population percentiles, and not an SLO.
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

BENCH_KEY = "synthetic-session-scale-key"
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
            queue = response.headers.get("x-censgate-redact-queue-ms")
            return {
                "status": response.status,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "queue_ms": int(queue) if queue and str(queue).isdigit() else None,
                "category": classify(response.status, payload),
                "payload": payload,
            }
    except urllib.error.HTTPError as err:
        try:
            payload = json.load(err)
        except Exception:
            payload = {}
        queue = err.headers.get("x-censgate-redact-queue-ms") if err.headers else None
        message = (payload.get("error") or {}).get("message") if isinstance(payload, dict) else None
        return {
            "status": err.code,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "queue_ms": int(queue) if queue and str(queue).isdigit() else None,
            "category": classify(err.code, payload),
            "message": message if message in STATIC else None,
            "payload": payload if isinstance(payload, dict) else {},
        }
    except Exception:
        return {
            "status": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
            "queue_ms": None,
            "category": "cancel_or_client_timeout",
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
    return {
        "status": result.get("status"),
        "elapsed_ms": result.get("elapsed_ms"),
        "queue_ms": result.get("queue_ms"),
        "category": result.get("category"),
        "message": result.get("message"),
    }


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
    def __init__(self, binary, env, cgroup, memory_max):
        self.binary = binary
        self.env = env
        self.cgroup = cgroup
        self.memory_max = memory_max
        self.proc = None
        self.base = None

    def start(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        if self.cgroup:
            root = Path(self.cgroup)
            if self.memory_max:
                subprocess.run(
                    ["sudo", "tee", str(root / "memory.max")],
                    input=f"{self.memory_max}\n".encode(),
                    stdout=subprocess.DEVNULL,
                    check=False,
                )
            subprocess.run(
                ["sudo", "tee", str(root / "memory.peak")],
                input=b"0\n",
                stdout=subprocess.DEVNULL,
                check=False,
            )
        log_path = Path("/tmp/redact-bench/probe-gateway.log")
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
    prefix = "synthetic-scale-" + uuid.uuid4().hex
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
        OTEL_SDK_DISABLED="true",
    )
    for key in ("CENSGATE_VAULT_NAMESPACE", "CENSGATE_POLICY_FILE", "CENSGATE_DEFAULT_PROFILE"):
        env.pop(key, None)
    return env


def parallel(calls):
    errors = []

    def run(index, fn):
        try:
            calls[index] = fn()
        except Exception as err:
            errors.append(str(err))

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(calls)]
    calls[:] = [None] * len(calls)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise RuntimeError(errors[0])
    return calls


def main():
    vault = os.environ.get("REDACT_BENCH_VAULT_ADDR", "")
    if urllib.parse.urlparse(vault).hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing non-local vault endpoint")
    binary = Path(os.environ.get("REDACT_BENCH_GATEWAY", "target/release/redact-gateway")).resolve()
    out_path = Path(os.environ.get("REDACT_BENCH_OUTPUT", "/opt/cursor/artifacts/redaction-session-scale.json"))
    result = {
        "note": "Single-run samples. Not population percentiles and not an approved SLO.",
        "map_doc_limit_default": 1249,
        "map_doc_slots": 8,
    }
    gw_cgroup = os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", "/sys/fs/cgroup/redact-gw")
    env = base_env()
    env.update(
        CENSGATE_REDACT_BATCH_INFLIGHT="1",
        CENSGATE_REDACT_BATCH_QUEUE_MS="15000",
        CENSGATE_REDACT_BATCH_QUEUE_DEPTH="4",
    )
    gateway = Gateway(binary, env, gw_cgroup, 4 * 1024 * 1024 * 1024)
    try:
        status = gateway.start()
        caps = status.get("capabilities") or {}
        result["advertised"] = {
            key: caps.get(key)
            for key in ("redact_texts_v1", "max_texts", "max_text_bytes", "max_total_bytes", "timeout_ms")
        }
        result["backend"] = status.get("token_map_backend")
        result["rss_after_start"] = gateway.cgroup_stat()

        fixtures = parity_fixtures()
        serial = []
        for text in fixtures:
            one = call(gateway.base, "/v1/redact", {"text": text, "profile": "reversible", "session_id": "parity-serial"}, 60)
            serial.extend(outputs(one))
        batched = call(gateway.base, "/v1/redact", {"texts": fixtures, "profile": "reversible", "session_id": "parity-batch"}, 60)
        batch_out = outputs(batched)
        emails = ["ada.one@example.test", "ada.two@example.test", "ada.three@example.test", "ada.four@example.test", "ada.five@example.test", "ada.six@example.test"]
        result["parity"] = {
            "leaves": len(fixtures),
            "equal": serial == batch_out and len(serial) == len(fixtures),
            "batch_category": batched["category"],
            "raw_email_survived": any(email in text for email in emails for text in batch_out),
            "unicode_kept": any("雪" in text for text in batch_out),
            "empty_kept": batch_out[8:10] == ["", " "] if len(batch_out) >= 10 else False,
        }
        print(json.dumps({"parity": result["parity"]}), flush=True)

        session = "scale-session"
        first_leaves = [leaf(i, "scalea") for i in range(800)]
        second_leaves = [leaf(i, "scaleb") for i in range(800)]
        first = call(gateway.base, "/v1/redact", {"texts": first_leaves, "profile": "reversible", "session_id": session}, 60)
        second = call(gateway.base, "/v1/redact", {"texts": second_leaves, "profile": "reversible", "session_id": session}, 60)
        first_out = outputs(first)
        second_out = outputs(second)
        follow = call(
            gateway.base,
            "/v1/redact",
            {"texts": [first_leaves[0], leaf(0, "scalec")], "profile": "reversible", "session_id": session},
            60,
        )
        follow_out = outputs(follow)
        restored = call(gateway.base, "/v1/restore", {"text": first_out[0] if first_out else "", "session_id": session}, 30)
        restored_second = call(
            gateway.base,
            "/v1/restore",
            {"text": second_out[0] if second_out else "", "session_id": session},
            30,
        )
        result["repeated_800"] = {
            "first": public(first),
            "second": public(second),
            "follow": public(follow),
            "first_token_reused": bool(first_out and follow_out and first_out[0] == follow_out[0].split(" synthetic")[0] or (first_out and follow_out and first_out[0] in follow_out[0])),
            "restore_first_matches": (restored.get("payload") or {}).get("text") == first_leaves[0],
            "restore_second_matches": (restored_second.get("payload") or {}).get("text") == second_leaves[0],
            "restore_first_category": restored["category"],
            "restore_second_category": restored_second["category"],
            "raw_email_survived": any("scalea" in text or "scaleb" in text for text in first_out + second_out),
        }
        print(json.dumps({"repeated_800": result["repeated_800"]}), flush=True)

        longer = call(
            gateway.base,
            "/v1/redact",
            {"texts": [long_leaf(i) for i in range(800)], "profile": "reversible", "session_id": "long-800"},
            45,
        )
        result["longer_800"] = public(longer)
        result["longer_800"]["leaf_bytes"] = len(long_leaf(1).encode())
        print(json.dumps({"longer_800": result["longer_800"]}), flush=True)

        queued = [None, None]

        def one(index):
            return call(
                gateway.base,
                "/v1/redact",
                {"texts": [leaf(i, f"queue{index}") for i in range(139)], "profile": "reversible", "session_id": f"queue-{index}"},
                60,
            )

        queued = parallel([lambda: one(0), lambda: one(1)])
        result["fair_queue_two_tenants"] = [public(item) for item in queued]
        print(json.dumps({"fair_queue": result["fair_queue_two_tenants"]}), flush=True)
        result["rss_after_primary"] = gateway.cgroup_stat()
    finally:
        gateway.stop()

    # Two replicas, one CPU each, distinct sessions.
    replicas = []
    try:
        second_cgroup = os.environ.get("REDACT_BENCH_GATEWAY_CGROUP_B", "/sys/fs/cgroup/redact-gw2")
        if Path(second_cgroup).is_dir():
            subprocess.run(
                ["sudo", "tee", second_cgroup.rstrip("/") + "/cpu.max"],
                input=b"100000 100000\n",
                stdout=subprocess.DEVNULL,
                check=False,
            )
        for cgroup in (gw_cgroup, second_cgroup):
            replica_env = base_env()
            replica_env.update(
                CENSGATE_REDACT_BATCH_INFLIGHT="1",
                CENSGATE_REDACT_BATCH_QUEUE_MS="0",
                CENSGATE_REDACT_BATCH_QUEUE_DEPTH="1",
            )
            replicas.append(Gateway(binary, replica_env, cgroup, None))
        for replica in replicas:
            replica.start()

        def hit(replica, name):
            return call(
                replica.base,
                "/v1/redact",
                {"texts": [leaf(i, name) for i in range(139)], "profile": "reversible", "session_id": name},
                60,
            )

        both = parallel([lambda: hit(replicas[0], "tenant-a"), lambda: hit(replicas[1], "tenant-b")])
        result["horizontal_1cpu_each"] = [public(item) for item in both]
        result["horizontal_rss"] = [replica.cgroup_stat() for replica in replicas]
        print(json.dumps({"horizontal": result["horizontal_1cpu_each"]}), flush=True)
    finally:
        for replica in replicas:
            replica.stop()

    # Overlapping writers on one session, two permits, small leaves.
    overlap = Gateway(binary, base_env(), gw_cgroup, None)
    overlap.env.update(
        CENSGATE_REDACT_BATCH_INFLIGHT="2",
        CENSGATE_REDACT_BATCH_QUEUE_MS="0",
        CENSGATE_REDACT_BATCH_QUEUE_DEPTH="1",
    )
    try:
        overlap.start()

        def side(tag):
            return call(
                overlap.base,
                "/v1/redact",
                {"texts": [leaf(i, tag) for i in range(20)], "profile": "reversible", "session_id": "overlap"},
                60,
            )

        pair = parallel([lambda: side("overa"), lambda: side("overb")])
        left = outputs(pair[0])
        right = outputs(pair[1])
        check = call(
            overlap.base,
            "/v1/redact",
            {"texts": [leaf(0, "overa"), leaf(0, "overb")], "profile": "reversible", "session_id": "overlap"},
            60,
        )
        checked = outputs(check)
        result["concurrent_same_session"] = {
            "writers": [public(item) for item in pair],
            "follow": public(check),
            "tokens_stable": bool(left and right and checked and left[0] in checked[0] and right[0] in checked[1] if len(checked) > 1 else False),
        }
        print(json.dumps({"concurrent_same_session": result["concurrent_same_session"]}), flush=True)
        result["overlap_rss"] = overlap.cgroup_stat()
    finally:
        overlap.stop()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"done": True, "output": str(out_path)}), flush=True)


if __name__ == "__main__":
    main()
