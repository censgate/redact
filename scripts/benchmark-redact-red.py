#!/usr/bin/env python3
"""RED load of the real gateway, NER, and local KV-v2.

Prints timings, statuses, and counts. Response bodies are not logs.
Candidate numbers in the output are measurements, not approved SLOs.
"""
import argparse
import json
import math
import os
from pathlib import Path
import socket
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

STATIC_MESSAGES = {
    "redact batch overloaded",
    "dependency unavailable: redact batch deadline exceeded",
    "dependency unavailable: token map write failed",
    "dependency unavailable: token map read failed",
    "dependency unavailable: batch tokenization requires a token map",
    "invalid redact request body",
    "texts must contain 1 to 800 strings",
    "redact batching is disabled",
    "invalid redact timeout",
    "redaction failed: batch detection or tokenization failed",
}


def percentile(samples, q):
    if not samples:
        return None
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(len(ordered) * q) - 1)]


def summarize(samples):
    if not samples:
        return None
    return {
        "n": len(samples),
        "p50_ms": round(statistics.median(samples), 1),
        "p95_ms": round(percentile(samples, 0.95), 1),
        "p99_ms": round(percentile(samples, 0.99), 1),
        "max_ms": round(max(samples), 1),
    }


def classify(status, payload):
    if status is None:
        return "cancel_or_client_timeout"
    err = {}
    if isinstance(payload, dict):
        err = payload.get("error") or {}
    kind = err.get("type") or ""
    message = err.get("message") or ""
    if status == 200:
        if isinstance(payload, dict) and payload.get("blocked") is True:
            return "policy"
        return "ok"
    if kind == "policy_violation" or status == 422:
        return "policy"
    if kind == "overload":
        return "overload"
    if "deadline exceeded" in message:
        return "deadline"
    if kind == "invalid_request_error" or status == 400:
        return "invalid_request"
    if kind == "dependency_unavailable":
        return "dependency"
    if status >= 500 or kind in ("redaction_error", "internal_error"):
        return "internal"
    return "other"


def safe_message(payload):
    if not isinstance(payload, dict):
        return None
    message = (payload.get("error") or {}).get("message")
    if message in STATIC_MESSAGES:
        return message
    return None


def request(base, body, timeout):
    raw = json.dumps(body).encode()
    req = urllib.request.Request(
        base + "/v1/redact",
        data=raw,
        headers={"Content-Type": "application/json"},
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.load(response)
            elapsed = (time.perf_counter() - started) * 1000
            queue = response.headers.get("x-censgate-redact-queue-ms")
            return {
                "status": response.status,
                "elapsed_ms": round(elapsed, 1),
                "queue_ms": int(queue) if queue and queue.isdigit() else None,
                "category": classify(response.status, payload),
                "blocked": bool(payload.get("blocked")) if isinstance(payload, dict) else None,
                "texts": payload.get("texts") if isinstance(payload, dict) else None,
                "text": payload.get("text") if isinstance(payload, dict) else None,
            }
    except urllib.error.HTTPError as err:
        elapsed = (time.perf_counter() - started) * 1000
        try:
            payload = json.load(err)
        except Exception:
            payload = {}
        queue = err.headers.get("x-censgate-redact-queue-ms") if err.headers else None
        return {
            "status": err.code,
            "elapsed_ms": round(elapsed, 1),
            "queue_ms": int(queue) if queue and str(queue).isdigit() else None,
            "category": classify(err.code, payload),
            "message": safe_message(payload),
            "error_type": (payload.get("error") or {}).get("type") if isinstance(payload, dict) else None,
        }
    except Exception:
        elapsed = (time.perf_counter() - started) * 1000
        return {
            "status": None,
            "elapsed_ms": round(elapsed, 1),
            "queue_ms": None,
            "category": "cancel_or_client_timeout",
        }


def short_leaf(i, tag):
    return f'synthetic record {i}: {tag}{i}@example.test; quoted "雪"\n'


def byte_leaf(i):
    pad = "synthetic-padding " * 30
    return f"{pad}bytefixture{i}@example.test\n"


def entity_leaf(i):
    return f"Alex Surname{i} met Blair Kind{i} near the synthetic office.\n"


def outputs_of(result):
    if result.get("texts") is not None:
        return result["texts"]
    if result.get("text") is not None:
        return [result["text"]]
    return []


def strip_text(result):
    result.pop("texts", None)
    result.pop("text", None)
    return result


def vault_version(vault, mount, prefix, session, token):
    req = urllib.request.Request(
        f"{vault}/v1/{mount}/metadata/{prefix}/default/{session}",
        headers={"X-Vault-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.load(response)
            return response.status, payload.get("data", {}).get("current_version")
    except urllib.error.HTTPError as err:
        return err.code, None


def cgroup_stat(path):
    if not path:
        return None
    root = Path(path)
    out = {}
    for key in ("memory.current", "memory.peak", "memory.max", "cpu.max"):
        file = root / key
        if file.is_file():
            out[key] = file.read_text().strip()
    stat = root / "cpu.stat"
    if stat.is_file():
        vals = {}
        for line in stat.read_text().splitlines():
            name, _, value = line.partition(" ")
            if name in ("usage_usec", "throttled_usec", "nr_throttled"):
                vals[name] = int(value)
        out["cpu_stat"] = vals
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", type=Path, default=Path("target/release/redact-gateway"))
    parser.add_argument("--output", type=Path, default=Path("redact-red.json"))
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--leaves", default="", help="comma-separated short leaf counts; skips admission, growth, and rate sections")
    args = parser.parse_args()
    only_leaves = [int(part) for part in args.leaves.split(",") if part.strip()]
    env = os.environ.copy()
    model = Path(env.get("CENSGATE_NER_MODEL_PATH", "/missing-ner-model"))
    runtime = Path(env.get("ORT_DYLIB_PATH", "/missing-onnx-runtime"))
    vault = env.get("REDACT_BENCH_VAULT_ADDR", "")
    token = env.get("REDACT_BENCH_VAULT_TOKEN", "")
    mount = env.get("REDACT_BENCH_VAULT_MOUNT", "")
    if urllib.parse.urlparse(vault).hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing non-local vault endpoint")
    for path in (model, model.parent / "tokenizer.json", runtime, args.gateway):
        if not path.is_file():
            print(json.dumps({"performance": "BLOCKED", "missing": str(path)}))
            return 2
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    prefix = "synthetic-red-bench-" + uuid.uuid4().hex
    env.update(
        CENSGATE_CONFIG_SOURCE="env",
        CENSGATE_NER_REQUIRED="true",
        CENSGATE_VAULT_BACKEND="vault_kv2",
        CENSGATE_VAULT_ADDR=vault,
        CENSGATE_VAULT_TOKEN=token,
        CENSGATE_VAULT_AUTH="token",
        CENSGATE_VAULT_MOUNT=mount,
        CENSGATE_VAULT_PATH_PREFIX=prefix,
        CENSGATE_AUTH_MODE="none",
        CENSGATE_REDACT_BATCH_ENABLED="true",
        OTEL_SDK_DISABLED="true",
    )
    env.setdefault("CENSGATE_REDACT_BATCH_INFLIGHT", "1")
    env.setdefault("CENSGATE_REDACT_BATCH_QUEUE_MS", "0")
    for key in ("CENSGATE_API_KEYS", "CENSGATE_VAULT_NAMESPACE", "CENSGATE_POLICY_FILE", "CENSGATE_DEFAULT_PROFILE"):
        env.pop(key, None)
    result = {
        "note": "Measurements only. No user-approved SLO exists. p99 on a small sample is the nearest-rank order statistic, not a population SLO.",
        "admission": {
            "inflight": env["CENSGATE_REDACT_BATCH_INFLIGHT"],
            "queue_ms": env["CENSGATE_REDACT_BATCH_QUEUE_MS"],
        },
        "shapes": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    log_path = args.output.with_suffix(".gateway.log")
    with log_path.open("w") as log:
        proc = subprocess.Popen(
            [str(args.gateway.resolve()), "--host", "127.0.0.1", "--port", str(port)],
            env=env,
            stdout=log,
            stderr=log,
        )
        gw_cgroup = os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", "")
        if gw_cgroup:
            subprocess.run(
                ["sudo", "tee", gw_cgroup.rstrip("/") + "/cgroup.procs"],
                input=f"{proc.pid}\n".encode(),
                check=True,
                stdout=subprocess.DEVNULL,
            )
        try:
            status = None
            for _ in range(120):
                if proc.poll() is not None:
                    raise RuntimeError("gateway exited during startup")
                try:
                    with urllib.request.urlopen(base + "/v1/compliance/status", timeout=2) as response:
                        status = json.load(response)
                        break
                except Exception:
                    time.sleep(0.25)
            else:
                raise RuntimeError("gateway startup timed out")
            caps = status.get("capabilities") or {}
            result["advertised"] = {key: caps.get(key) for key in ("redact_texts_v1", "max_texts", "max_text_bytes", "max_total_bytes", "timeout_ms")}
            if caps.get("redact_texts_v1") is not True or status.get("token_map_backend") != "vault_kv2":
                raise RuntimeError("real batch KV gateway required")

            def checkpoint():
                args.output.write_text(json.dumps(result, indent=2) + "\n")

            # Serial versus batch parity on one short shape. Texts are compared, then dropped.
            parity_leaves = [short_leaf(i, "batchfixture") for i in range(8)]
            serial_out = []
            for leaf in parity_leaves:
                one = request(base, {"text": leaf, "profile": "reversible", "session_id": "parity-serial"}, 60)
                serial_out.extend(outputs_of(one))
            batched = request(base, {"texts": parity_leaves, "profile": "reversible", "session_id": "parity-batch"}, 60)
            batch_out = outputs_of(batched)
            result["parity"] = {
                "leaves": 8,
                "equal": serial_out == batch_out,
                "serial_ok": len(serial_out) == 8,
                "batch_category": batched.get("category"),
                "raw_email_survived": any(f"batchfixture{i}@example.test" in text for i, text in enumerate(batch_out)),
            }
            print(json.dumps({"parity": result["parity"]}), flush=True)
            checkpoint()

            shapes = [
                ("short", 139, [short_leaf(i, "batchfixture") for i in range(139)]),
                ("short", 347, [short_leaf(i, "batchfixture") for i in range(347)]),
                ("short", 800, [short_leaf(i, "batchfixture") for i in range(800)]),
                ("bytes", 64, [byte_leaf(i) for i in range(64)]),
                ("entities", 64, [entity_leaf(i) for i in range(64)]),
            ]
            if only_leaves:
                shapes = [row for row in shapes if row[0] == "short" and row[1] in only_leaves]
            for kind, count, leaves in shapes:
                walls = []
                queues = []
                categories = []
                leaked = False
                for sample in range(args.samples):
                    got = request(
                        base,
                        {"texts": leaves, "profile": "reversible", "session_id": f"{kind}-{count}-{sample}"},
                        180,
                    )
                    categories.append(got["category"])
                    if got["category"] == "ok":
                        walls.append(got["elapsed_ms"])
                        if got.get("queue_ms") is not None:
                            queues.append(got["queue_ms"])
                        texts_out = outputs_of(got)
                        leaked = leaked or any(
                            f"batchfixture{i}@example.test" in text or f"bytefixture{i}@example.test" in text
                            for i, text in enumerate(texts_out)
                        )
                        if kind == "entities":
                            leaked = leaked or any("Surname" in text or f"Kind{i}" in text for i, text in enumerate(texts_out))
                    print(json.dumps({"shape": kind, "leaves": count, "sample": sample, "category": got["category"], "elapsed_ms": got["elapsed_ms"]}), flush=True)
                row = {
                    "kind": kind,
                    "leaves": count,
                    "bytes": sum(len(leaf.encode()) for leaf in leaves),
                    "categories": categories,
                    "latency": summarize(walls),
                    "queue_ms": summarize(queues) if queues else {"n": 0},
                    "raw_email_survived": leaked,
                }
                if walls:
                    row["derived_single_flight_per_minute"] = round(60000 / statistics.median(walls), 2)
                result["shapes"].append(row)
                checkpoint()

            if only_leaves:
                result["cgroup"] = {
                    "gateway": cgroup_stat(os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", "")),
                    "openbao": cgroup_stat(os.environ.get("REDACT_BENCH_VAULT_CGROUP", "")),
                }
                checkpoint()
                print(json.dumps({"done": True, "shapes": len(result["shapes"])}), flush=True)
                return 0

            # One admitted request, three others rejected. No queue.
            held = {}

            def hold():
                held["result"] = request(
                    base,
                    {"texts": [short_leaf(i, "holdfixture") for i in range(139)], "profile": "reversible", "session_id": "hold"},
                    180,
                )

            thread = threading.Thread(target=hold)
            thread.start()
            time.sleep(0.2)
            rejected = [
                strip_text(request(base, {"texts": [short_leaf(i, "extrafixture") for i in range(8)], "profile": "reversible", "session_id": f"extra-{i}"}, 30))
                for i in range(3)
            ]
            thread.join()
            result["overload"] = {
                "admitted": {key: held.get("result", {}).get(key) for key in ("category", "elapsed_ms", "queue_ms", "status")},
                "rejected": rejected,
            }
            print(json.dumps({"overload_rejected": [row.get("category") for row in rejected]}), flush=True)
            checkpoint()

            # Same session, second arrival while the first is admitted.
            shared = {}

            def first():
                shared["first"] = request(
                    base,
                    {"texts": [short_leaf(i, "sharedfixture") for i in range(80)], "profile": "reversible", "session_id": "shared"},
                    180,
                )

            thread = threading.Thread(target=first)
            thread.start()
            time.sleep(0.2)
            shared["second"] = request(
                base,
                {"texts": [short_leaf(i, "othershared") for i in range(8)], "profile": "reversible", "session_id": "shared"},
                30,
            )
            thread.join()
            code, version = vault_version(vault, mount, prefix, "shared", token)
            first_out = outputs_of(shared.get("first", {}))
            result["shared_session_inflight_1"] = {
                "first": shared.get("first", {}).get("category"),
                "second": shared.get("second", {}).get("category"),
                "second_error_type": shared.get("second", {}).get("error_type"),
                "vault_http": code,
                "vault_version": version,
                "raw_email_survived": any("sharedfixture" in text and "@example.test" in text for text in first_out),
            }
            checkpoint()

            # Cumulative mappings on one session. 600 + 600 stays under the 10000-string document; the third add crosses it.
            growth = []
            for step, count, tag in ((1, 600, "growtha"), (2, 600, "growthb"), (3, 200, "growthc")):
                got = request(
                    base,
                    {"texts": [short_leaf(i, tag) for i in range(count)], "profile": "reversible", "session_id": "growth"},
                    180,
                )
                code, version = vault_version(vault, mount, prefix, "growth", token)
                growth.append({
                    "step": step,
                    "leaves": count,
                    "category": got["category"],
                    "message": got.get("message"),
                    "elapsed_ms": got["elapsed_ms"],
                    "vault_http": code,
                    "vault_version": version,
                    "raw_email_survived": any(f"{tag}{i}@example.test" in text for i, text in enumerate(outputs_of(got))),
                })
                print(json.dumps(growth[-1]), flush=True)
            result["session_growth"] = growth
            checkpoint()

            over = strip_text(request(base, {"texts": [short_leaf(i, "overfixture") for i in range(801)], "profile": "reversible", "session_id": "over"}, 30))
            result["over_cap"] = over
            checkpoint()

            # Client gives up during the first micro-batches. The write must not appear.
            request(base, {"texts": [short_leaf(i, "cancelfixture") for i in range(347)], "profile": "reversible", "session_id": "cancel-me"}, 1.0)
            time.sleep(3)
            code, version = vault_version(vault, mount, prefix, "cancel-me", token)
            result["cancel_before_put"] = {"client_timeout_s": 1, "vault_http": code, "vault_version": version}
            checkpoint()

            # Sustained single-flight rate for the smaller shape.
            sustain_seconds = 20
            sustain_leaves = [short_leaf(i, "ratefixture") for i in range(139)]
            started = time.perf_counter()
            sustain = []
            while time.perf_counter() - started < sustain_seconds:
                got = request(base, {"texts": sustain_leaves, "profile": "reversible", "session_id": f"rate-{len(sustain)}"}, 60)
                sustain.append(got["category"])
            elapsed = time.perf_counter() - started
            ok = sustain.count("ok")
            result["sustained_single_flight"] = {
                "leaves": 139,
                "window_s": round(elapsed, 1),
                "completed_ok": ok,
                "categories": sustain,
                "ok_per_minute": round(ok / elapsed * 60, 2) if elapsed else None,
            }
            print(json.dumps(result["sustained_single_flight"]), flush=True)
            checkpoint()

            result["cgroup"] = {
                "gateway": cgroup_stat(os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", "")),
                "openbao": cgroup_stat(os.environ.get("REDACT_BENCH_VAULT_CGROUP", "")),
            }
            checkpoint()
            print(json.dumps({"done": True, "shapes": len(result["shapes"])}), flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
