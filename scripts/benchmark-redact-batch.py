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
        with urllib.request.urlopen(req, timeout=35) as response:
            return json.load(response)
    except urllib.error.HTTPError as err:
        # Bodies may contain content or credentials; report status only.
        raise RuntimeError(f"HTTP {err.code} from local dependency") from None


def percentile(samples, q):
    return sorted(samples)[max(0, math.ceil(len(samples) * q) - 1)]


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
            for leaves in (139, 347, 800):
                fixture = [f"synthetic record {i}: batchfixture{i}@example.test; quoted \"雪\"\n" for i in range(leaves)]
                for mode in ("serial", "batch"):
                    walls, requests, writes = [], [], []
                    for sample in range(args.samples + 1):
                        session = f"{mode}-{leaves}-{sample}"
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
                        if any(f"batchfixture{i}@example.test" in output for i, output in enumerate(outputs)):
                            raise RuntimeError("synthetic fixture redaction coverage failed")
                        metadata = call(vault, f"/v1/{mount}/metadata/{prefix}/default/{session}", token=token)
                        version = metadata["data"]["current_version"]
                        if sample:  # sample 0 warms NER/transport separately for each shape/mode
                            walls.append(elapsed)
                            requests.append(leaves if mode == "serial" else 1)
                            writes.append(version)
                    rows.append(dict(mode=mode, leaves=leaves, samples=args.samples, warm=True, p50_ms=statistics.median(walls), p95_ms=percentile(walls, .95), wall_ms=walls, http_requests=requests, vault_successful_writes=writes))
            result = dict(environment=dict(machine=platform.platform(), cpu=platform.processor(), cpu_count=os.cpu_count(), gateway_version=status["version"], vault_version=health.get("version"), model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(), runtime=str(runtime), profiling="Sequential leaf inference; use gateway detect spans for ONNX share. KV metadata versions count successful writes, not rejected CAS attempts."), rows=rows)
            args.output.write_text(json.dumps(result, indent=2) + "\n")
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
