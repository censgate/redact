#!/usr/bin/env python3
"""Local real gateway + required ONNX NER + KV-v2 bench; never mock perf proof."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def call(base, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=200) as response:
            return json.load(response)
    except urllib.error.HTTPError as err:
        # Bodies may contain content or credentials; report status only.
        raise RuntimeError(f"HTTP {err.code} from local dependency") from None


def percentile(samples, q):
    return sorted(samples)[max(0, math.ceil(len(samples) * q) - 1)]


def count_json_strings(value):
    """Object keys plus string values. Matches the OpenBao JSON string cap."""
    if isinstance(value, dict):
        return sum(1 + count_json_strings(item) for item in value.values())
    if isinstance(value, list):
        return sum(count_json_strings(item) for item in value)
    if isinstance(value, str):
        return 1
    return 0


def mapping_document(count):
    mappings = [{
        "token": f"[EMAIL_ADDRESS_{i}]",
        "entity_type": "EMAIL_ADDRESS",
        "sealed_value": "c3ludGhldGljLXNlYWxlZC12YWx1ZS1ub3QtcGlp",
        "created_at": "2026-11-06T12:00:00Z",
    } for i in range(count)]
    return {"data": {"mappings": mappings, "expires_at": "2099-01-01T00:00:00Z"}, "options": {"cas": 0}}


def write_document(vault, mount, path, token, count):
    raw = json.dumps(mapping_document(count)).encode()
    req = urllib.request.Request(
        f"{vault}/v1/{mount}/data/{path}",
        data=raw,
        headers={"Content-Type": "application/json", "X-Vault-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, len(raw)
    except urllib.error.HTTPError as err:
        return err.code, len(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check dependencies without starting services")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--output", type=Path, default=Path("redact-batch-realstack.json"))
    parser.add_argument("--gateway", type=Path, default=Path("target/release/redact-gateway"))
    args = parser.parse_args()
    env = os.environ.copy()
    model = Path(env.get("CENSGATE_NER_MODEL_PATH", "/missing-ner-model"))
    runtime = Path(env.get("ORT_DYLIB_PATH", "/missing-onnx-runtime"))
    vault = env.get("REDACT_BENCH_VAULT_ADDR", "")
    token = env.get("REDACT_BENCH_VAULT_TOKEN", "")
    mount = env.get("REDACT_BENCH_VAULT_MOUNT", "")
    missing = []
    for name, path in [("exported NER model (CENSGATE_NER_MODEL_PATH)", model), ("NER tokenizer.json beside model", model.parent / "tokenizer.json"), ("ONNX runtime (ORT_DYLIB_PATH)", runtime), ("release gateway binary", args.gateway)]:
        if not path.is_file():
            missing.append(name)
    if not vault:
        missing.append("isolated local OpenBao/KV-v2 endpoint (REDACT_BENCH_VAULT_ADDR)")
    elif urllib.parse.urlparse(vault).hostname not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("refusing non-local vault endpoint")
    if not token:
        missing.append("local-only vault credential (REDACT_BENCH_VAULT_TOKEN)")
    if not mount:
        missing.append("dedicated local KV-v2 mount (REDACT_BENCH_VAULT_MOUNT)")
    if missing:
        print(json.dumps({"performance": "BLOCKED", "missing": missing}, indent=2))
        return 2
    health = call(vault, "/v1/sys/health", token=token)
    if args.check:
        print("Real-stack dependencies present; no measurements made.")
        return 0
    if args.samples < 2:
        raise SystemExit("at least two samples required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    prefix = "synthetic-batch-bench-" + uuid.uuid4().hex
    env.update(CENSGATE_CONFIG_SOURCE="env", CENSGATE_NER_REQUIRED="true", CENSGATE_VAULT_BACKEND="vault_kv2", CENSGATE_VAULT_ADDR=vault, CENSGATE_VAULT_TOKEN=token, CENSGATE_VAULT_AUTH="token", CENSGATE_VAULT_MOUNT=mount, CENSGATE_VAULT_PATH_PREFIX=prefix, CENSGATE_AUTH_MODE="none", CENSGATE_REDACT_BATCH_ENABLED="true", OTEL_SDK_DISABLED="true")
    # Do not inherit a caller's auth/namespace/profile overlays for this isolated run.
    for key in ("CENSGATE_API_KEYS", "CENSGATE_VAULT_NAMESPACE", "CENSGATE_POLICY_FILE", "CENSGATE_DEFAULT_PROFILE"):
        env.pop(key, None)
    rows = []
    with args.output.with_suffix(".gateway.log").open("w") as log:
        proc = subprocess.Popen([str(args.gateway.resolve()), "--host", "127.0.0.1", "--port", str(port)], env=env, stdout=log, stderr=log)
        gw_cgroup = os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", "")
        if gw_cgroup:
            subprocess.run(["sudo", "tee", gw_cgroup.rstrip("/") + "/cgroup.procs"], input=f"{proc.pid}\n".encode(), check=True, stdout=subprocess.DEVNULL)
        try:
            for _ in range(120):
                if proc.poll() is not None:
                    raise RuntimeError("required-NER gateway failed startup; see local gateway log")
                try:
                    status = call(base, "/v1/compliance/status")
                    break
                except (OSError, RuntimeError):
                    time.sleep(0.25)
            else:
                raise RuntimeError("local gateway startup timed out")
            if status.get("token_map_backend") != "vault_kv2" or status.get("capabilities", {}).get("redact_texts_v1") is not True:
                raise RuntimeError("real KV-v2 batch gateway required")
            result = dict(environment=dict(machine=platform.platform(), cpu=platform.processor(), cpu_count=os.cpu_count(), gateway_version=status["version"], vault_version=health.get("version"), model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(), runtime=str(runtime), profiling="Sequential leaf inference on one CPU. OpenBao is capped at 250mCPU and 256Mi. KV metadata versions count successful writes, not rejected CAS attempts. timeout_ms below is the measurement ceiling, not the proposed deadline.", shape="gateway-1cpu openbao-250mCPU-256Mi strings-10000"), rows=rows)
            result_caps = status.get("capabilities", {})
            result["advertised_capabilities"] = {k: result_caps.get(k) for k in ("redact_texts_v1", "max_texts", "max_text_bytes", "max_total_bytes", "timeout_ms")}
            def checkpoint():
                args.output.write_text(json.dumps(result, indent=2) + "\n")
            def one_pass(mode, leaves, session, fixture):
                common = {"profile": "reversible", "session_id": session}
                start = time.perf_counter()
                if mode == "serial":
                    outputs = [call(base, "/v1/redact", dict(common, text=leaf))["text"] for leaf in fixture]
                else:
                    response = call(base, "/v1/redact", dict(common, texts=fixture))
                    if response.get("blocked") or len(response.get("texts", [])) != leaves:
                        raise RuntimeError("batch blocked or shape mismatch")
                    outputs = response["texts"]
                elapsed = (time.perf_counter() - start) * 1000
                if any(f"batchfixture{i}@example.test" in output or f"accumfixture{i}@example.test" in output for i, output in enumerate(outputs)):
                    raise RuntimeError("synthetic fixture redaction coverage failed")
                metadata = call(vault, f"/v1/{mount}/metadata/{prefix}/default/{session}", token=token)
                return elapsed, metadata["data"]["current_version"]
            for leaves in (139, 347, 800):
                fixture = [f"synthetic record {i}: batchfixture{i}@example.test; quoted \"雪\"\n" for i in range(leaves)]
                for mode in ("serial", "batch"):
                    cold_wall = None
                    walls, requests, writes = [], [], []
                    try:
                        for sample in range(args.samples + 1):
                            elapsed, version = one_pass(mode, leaves, f"{mode}-{leaves}-{sample}", fixture)
                            if sample == 0:
                                cold_wall = elapsed
                                rows.append(dict(mode=mode, leaves=leaves, phase="cold", samples=1, wall_ms=elapsed, http_requests=leaves if mode == "serial" else 1, vault_successful_writes=version, process_cold=(leaves == 139 and mode == "serial")))
                            else:
                                walls.append(elapsed)
                                requests.append(leaves if mode == "serial" else 1)
                                writes.append(version)
                    except RuntimeError as err:
                        rows.append(dict(mode=mode, leaves=leaves, phase="warm" if cold_wall is not None else "cold", error=str(err)))
                        checkpoint()
                        print(json.dumps(result, indent=2))
                        return 1
                    rows.append(dict(mode=mode, leaves=leaves, phase="warm", samples=args.samples, p50_ms=statistics.median(walls), p95_ms=percentile(walls, .95), wall_ms=walls, http_requests=requests, vault_successful_writes=writes))
                    if mode == "batch":
                        # Same shard, existing map, new entities. No split on overflow.
                        accumulated = [f"synthetic record {i}: accumfixture{i}@example.test; quoted \"雪\"\n" for i in range(leaves)]
                        try:
                            elapsed, version = one_pass(mode, leaves, f"batch-{leaves}-{args.samples}", accumulated)
                            rows.append(dict(mode=mode, leaves=leaves, phase="accumulated", samples=1, wall_ms=elapsed, http_requests=1, vault_successful_writes=version))
                        except RuntimeError as err:
                            rows.append(dict(mode=mode, leaves=leaves, phase="accumulated", error=str(err)))
                    checkpoint()
            # Largest realistic one-document map at this listener cap. A hit is
            # not proof the setting is safe for production sessions.
            accepted = 0
            accepted_bytes = 0
            rejected_at = None
            probe = 128
            while probe <= 20000:
                code, nbytes = write_document(vault, mount, f"{prefix}/capacity-{probe}", token, probe)
                if code != 200:
                    rejected_at = probe
                    break
                accepted, accepted_bytes = probe, nbytes
                probe *= 2
            lo, hi = accepted, rejected_at or accepted
            while rejected_at and lo + 1 < hi:
                mid = (lo + hi) // 2
                code, nbytes = write_document(vault, mount, f"{prefix}/capacity-{mid}", token, mid)
                if code == 200:
                    accepted, accepted_bytes, lo = mid, nbytes, mid
                else:
                    hi = mid
            result["map_capacity"] = {
                "listener_string_limit_under_test": 10000,
                "json_strings_keys_plus_values_at_accepted": count_json_strings(mapping_document(accepted)) if accepted else 0,
                "mapping_shape": "token, entity_type, sealed_value, created_at",
                "max_accepted_mappings": accepted,
                "max_accepted_body_bytes": accepted_bytes,
                "first_rejected_mappings": hi if rejected_at else None,
                "note": "Keys and values both count. Raising the listener does not split a session shard.",
            }
            if accepted:
                code, _ = write_document(vault, mount, f"{prefix}/default/near-cap", token, accepted)
                if code != 200:
                    result["near_cap"] = {"seed_status": code}
                else:
                    extra = [f"synthetic record {i}: nearcap{i}@example.test; quoted \"雪\"\n" for i in range(20)]
                    try:
                        call(base, "/v1/redact", {"profile": "reversible", "session_id": "near-cap", "texts": extra})
                        version = call(vault, f"/v1/{mount}/metadata/{prefix}/default/near-cap", token=token)["data"]["current_version"]
                        result["near_cap"] = {"seed_mappings": accepted, "added": 20, "result": "accepted", "vault_version": version}
                    except RuntimeError as err:
                        version = call(vault, f"/v1/{mount}/metadata/{prefix}/default/near-cap", token=token)["data"]["current_version"]
                        result["near_cap"] = {"seed_mappings": accepted, "added": 20, "result": str(err), "vault_version": version}
            concurrent = {}
            def worker(name, leaves):
                body = {"profile": "reversible", "session_id": "concurrent-shared", "texts": [f"synthetic record {i}: {name}{i}@example.test\n" for i in range(leaves)]}
                try:
                    call(base, "/v1/redact", body)
                    concurrent[name] = "ok"
                except RuntimeError as err:
                    concurrent[name] = str(err)
            threads = [threading.Thread(target=worker, args=(name, 40)) for name in ("left", "right")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            try:
                version = call(vault, f"/v1/{mount}/metadata/{prefix}/default/concurrent-shared", token=token)["data"]["current_version"]
            except RuntimeError:
                version = None
            result["concurrent_same_session"] = {"leaves_each": 40, "writers": concurrent, "vault_version": version}
            def cgroup_stat(path, name):
                if not path:
                    return None
                root = Path(path)
                out = {"name": name}
                for key in ("memory.current", "memory.peak", "memory.max", "cpu.max"):
                    file = root / key
                    if file.is_file():
                        out[key] = file.read_text().strip()
                stat = root / "cpu.stat"
                if stat.is_file():
                    vals = {}
                    for line in stat.read_text().splitlines():
                        k, _, v = line.partition(" ")
                        if k in ("usage_usec", "throttled_usec", "nr_throttled"):
                            vals[k] = int(v)
                    out["cpu_stat"] = vals
                return out
            result["cgroup"] = {
                "gateway": cgroup_stat(os.environ.get("REDACT_BENCH_GATEWAY_CGROUP", ""), "gateway-1cpu"),
                "openbao": cgroup_stat(os.environ.get("REDACT_BENCH_VAULT_CGROUP", ""), "openbao-250mCPU-256Mi"),
            }
            checkpoint()
            print(json.dumps(result, indent=2))
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
