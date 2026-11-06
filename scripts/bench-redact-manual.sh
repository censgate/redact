#!/bin/bash
# Manual redact / ONNX / OpenBao load entrypoint.
#
# Not a CI step. A future scheduler may invoke this script; this repo does not
# create that scheduler. Fast correctness tests stay in cargo test.
#
# Hard cap under test: 1 CPU and 2Gi, which are the AKS limits. The 100m CPU
# request is the scheduling weight under contention, not this cap. A separate
# 64-leaf sample at 100m is recorded after the limit run and labeled as such.
set -euo pipefail

if [[ "${CI:-}" == "true" || -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "bench-redact-manual: refused in CI" >&2
  exit 2
fi

: "${REDACT_BENCH_VAULT_ADDR:?}"
: "${REDACT_BENCH_VAULT_TOKEN:?}"
: "${REDACT_BENCH_VAULT_MOUNT:?}"
: "${CENSGATE_NER_MODEL_PATH:?}"
: "${ORT_DYLIB_PATH:?}"

root="/sys/fs/cgroup/redact-gw-2gi"
if [[ ! -d "$root" ]]; then
  sudo mkdir -p "$root"
fi
printf '%s\n' '100000 100000' | sudo tee "$root/cpu.max" >/dev/null
printf '%s\n' '2147483648' | sudo tee "$root/memory.max" >/dev/null
printf '%s\n' '0' | sudo tee "$root/memory.swap.max" >/dev/null

export REDACT_BENCH_GATEWAY_CGROUP="$root"
export REDACT_BENCH_GATEWAY="${REDACT_BENCH_GATEWAY:-target/release/redact-gateway}"
export REDACT_BENCH_OUTPUT="${REDACT_BENCH_OUTPUT:-/opt/cursor/artifacts/redaction-batching-openloop-2gi.json}"
export LD_LIBRARY_PATH="$(dirname "$ORT_DYLIB_PATH")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

cd "$(dirname "$0")/.."
python3 -u scripts/benchmark-redact-openloop.py

# Capacity illustration only. 100m is the request, not the limit.
printf '%s\n' '10000 100000' | sudo tee "$root/cpu.max" >/dev/null
python3 - << 'PY'
import importlib.util, json, os
from pathlib import Path
spec = importlib.util.spec_from_file_location("ol", "scripts/benchmark-redact-openloop.py")
ol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ol)
binary = Path(os.environ["REDACT_BENCH_GATEWAY"]).resolve()
cgroup = os.environ["REDACT_BENCH_GATEWAY_CGROUP"]
texts = [ol.leaf(i, "share") for i in range(64)]
row = ol.one_shot(binary, cgroup, {"CENSGATE_NER_INTRA_THREADS": "1"}, texts, "cpu-request-100m")
row["note"] = "64 short leaves at the 100m scheduling request, not the 1 CPU limit"
out = Path("/opt/cursor/artifacts/redaction-batching-100m.json")
out.write_text(json.dumps(row, indent=2) + "\n")
print(json.dumps({"cpu_request_100m": row}), flush=True)
PY
printf '%s\n' '100000 100000' | sudo tee "$root/cpu.max" >/dev/null
echo "bench-redact-manual: cpu.max restored to 1"
