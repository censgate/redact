#!/usr/bin/env bash
# Opt-in redact-gateway bench. Not CI. Not the 32× Presidio number.
#
# The published 32× (docs/benchmarks/results-20260418-175909.md) is redact-api
# vs Presidio, concurrency 1, pattern-only (email/phone/SSN). Do not quote it
# for the NER-required gateway image.
#
# Matrix (minimum):
#   - pattern-only vs NER-on (CENSGATE_NER_REQUIRED=true on the target)
#   - short (~20 tokens) vs long (~400+)
#   - concurrency 1 / 5 / 20
#   - token map: vault_kv2 (required path); off only as a negative control
#   - unique sessions vs same session_id (CAS)
#   - restore-after-scale when GATEWAY_URL_B is set (pod B restores pod A)
#
# Usage:
#   GATEWAY_URL=http://127.0.0.1:8080 \
#   GATEWAY_API_KEY=dev-key \
#   ./scripts/bench-gateway-ner.sh
#
# Optional:
#   GATEWAY_URL_B=http://gateway-b:8080   # second replica for restore-after-scale
#   BENCH_CONCURRENCY="1 5 20"
#   BENCH_SESSION_MODE=unique|same|both   # default both
set -euo pipefail

BASE="${GATEWAY_URL:-${PLATFORM_REDACT_GATEWAY_URL:-}}"
if [[ -z "${BASE}" ]]; then
  echo "skip: GATEWAY_URL unset"
  exit 0
fi
BASE="${BASE%/}"
BASE_B="${GATEWAY_URL_B:-}"
BASE_B="${BASE_B%/}"
KEY="${GATEWAY_API_KEY:-${PLATFORM_REDACT_GATEWAY_API_KEY:-}}"
AUTH=()
if [[ -n "${KEY}" ]]; then
  AUTH=(-H "Authorization: Bearer ${KEY}")
fi
CONCS="${BENCH_CONCURRENCY:-1 5 20}"
SESSION_MODE="${BENCH_SESSION_MODE:-both}"
ITERS="${BENCH_ITERS:-8}"
ALLOW_ERRORS="${BENCH_ALLOW_ERRORS:-0}"

short_text='Ada Lovelace emailed john.doe@example.com from London.'
long_text="$(python3 - <<'PY'
print(("Ada Lovelace met Alan Turing at Bletchley Park. " * 40).strip())
PY
)"

pattern_text='Contact john.doe@example.com or +1-202-555-0188, SSN 078-05-1120.'

curl_json() {
  local url="$1"
  local body="$2"
  local out
  out="$(mktemp)"
  local code
  code="$(curl -sS -o "${out}" -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    "${AUTH[@]}" \
    -d "${body}" \
    "${url}" || true)"
  echo "${code}" "${out}"
}

redact_body() {
  local text="$1"
  local session="$2"
  python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1], "session_id": sys.argv[2], "profile": "reversible"}))' \
    "${text}" "${session}"
}

restore_body() {
  local text="$1"
  local session="$2"
  python3 -c 'import json,sys; print(json.dumps({"text": sys.argv[1], "session_id": sys.argv[2]}))' \
    "${text}" "${session}"
}

percentile() {
  python3 -c '
import sys
vals=sorted(float(x) for x in sys.stdin if x.strip())
if not vals:
    print("nan")
    raise SystemExit
def pct(p):
    if len(vals)==1:
        return vals[0]
    k=(len(vals)-1)*p/100.0
    f=int(k); c=min(f+1,len(vals)-1)
    return vals[f]+(vals[c]-vals[f])*(k-f)
print(f"n={len(vals)} p50={pct(50):.1f} p99={pct(99):.1f} max={vals[-1]:.1f}")
'
}

run_slice() {
  local name="$1"
  local url="$2"
  local text="$3"
  local conc="$4"
  local session_fixed="$5"
  local distinct_pii="${6:-0}"
  local rounds="${7:-1}"
  local ms_file err_file
  ms_file="$(mktemp)"
  err_file="$(mktemp)"
  local i r pids=()
  local start end
  start="$(date +%s%N)"
  for ((r = 0; r < rounds; r++)); do
    pids=()
    for ((i = 0; i < conc; i++)); do
      (
        local session="${session_fixed}"
        if [[ -z "${session}" ]]; then
          session="bench-$(python3 -c 'import uuid; print(uuid.uuid4())')"
        fi
        local payload="${text}"
        if [[ "${distinct_pii}" == "1" ]]; then
          payload="$(python3 -c 'import sys; i=int(sys.argv[1]); base=sys.argv[2]; print(f"{base} Agent {i} emailed agent{i}@example{i}.com from Site{i}.")' "$((r * conc + i))" "${text}")"
        fi
        local body
        body="$(redact_body "${payload}" "${session}")"
        local t0 t1
        t0="$(date +%s%N)"
        read -r code out <<< "$(curl_json "${url}/v1/redact" "${body}")"
        t1="$(date +%s%N)"
        if [[ "${code}" == "200" ]]; then
          if ! python3 -c 'import json,sys; t=json.load(open(sys.argv[1])).get("text",""); sys.exit(0 if "[" in t else 1)' "${out}"; then
            echo "1" >> "${err_file}"
            echo "  fail ${name} conc=${conc} no token placeholders in response" >&2
          else
            python3 -c "print((${t1}-${t0})/1e6)" >> "${ms_file}"
          fi
        else
          echo "1" >> "${err_file}"
          echo "  fail ${name} conc=${conc} http=${code} body=$(head -c 160 "${out}")" >&2
        fi
        rm -f "${out}"
      ) &
      pids+=("$!")
    done
    local pid
    for pid in "${pids[@]}"; do
      wait "${pid}" || true
    done
  done
  end="$(date +%s%N)"
  local wall errors ok
  wall="$(python3 -c "print((${end}-${start})/1e6)")"
  errors="$(wc -l < "${err_file}" | tr -d ' ')"
  ok="$(wc -l < "${ms_file}" | tr -d ' ')"
  local stats
  stats="$(percentile < "${ms_file}")"
  local rps
  rps="$(python3 -c "print(round(${ok} / max(${wall}/1000.0, 0.001), 2))")"
  echo "${name} conc=${conc} rounds=${rounds} ok=${ok} errors=${errors} rps=${rps} wall_ms=${wall} ${stats}"
  rm -f "${ms_file}" "${err_file}"
  if [[ "${errors}" != "0" && "${ALLOW_ERRORS}" != "1" ]]; then
    echo "FAIL ${name}: ${errors} unexpected HTTP responses" >&2
    return 1
  fi
}

echo "gateway ${BASE}"
echo "NOTE: do not compare these numbers to the 32× Presidio redact-api result."
echo "slice: pattern vs NER depends on whether the target loaded an ONNX model."

failed=0
for conc in ${CONCS}; do
  if [[ "${SESSION_MODE}" == "unique" || "${SESSION_MODE}" == "both" ]]; then
    run_slice "pattern unique" "${BASE}" "${pattern_text}" "${conc}" "" 0 "${ITERS}" || failed=1
    run_slice "short unique" "${BASE}" "${short_text}" "${conc}" "" 0 "${ITERS}" || failed=1
    run_slice "long unique" "${BASE}" "${long_text}" "${conc}" "" 0 1 || failed=1
  fi
  if [[ "${SESSION_MODE}" == "same" || "${SESSION_MODE}" == "both" ]]; then
    # Distinct PII per writer so skip-empty-put does not hide CAS contention.
    shared="bench-shared-$(python3 -c 'import uuid; print(uuid.uuid4())')-${conc}"
    run_slice "short same-session" "${BASE}" "${short_text}" "${conc}" "${shared}" 1 "${ITERS}" || failed=1
    shared_long="bench-shared-long-$(python3 -c 'import uuid; print(uuid.uuid4())')-${conc}"
    run_slice "long same-session" "${BASE}" "${long_text}" "${conc}" "${shared_long}" 1 1 || failed=1
  fi
done
if [[ "${failed}" != "0" ]]; then
  echo "FAIL: one or more slices returned unexpected HTTP" >&2
  exit 1
fi

if [[ -n "${BASE_B}" ]]; then
  echo "restore-after-scale: mint on ${BASE}, restore on ${BASE_B}"
  session="bench-restore-$(python3 -c 'import uuid; print(uuid.uuid4())')"
  body="$(redact_body "${short_text}" "${session}")"
  read -r code out <<< "$(curl_json "${BASE}/v1/redact" "${body}")"
  redacted="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("text",""))' "${out}" 2>/dev/null || cat "${out}")"
  rm -f "${out}"
  if [[ "${code}" != "200" ]]; then
    echo "FAIL mint http=${code}"
    exit 1
  fi
  rbody="$(restore_body "${redacted}" "${session}")"
  read -r rcode rout <<< "$(curl_json "${BASE_B}/v1/restore" "${rbody}")"
  restored="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("text",""))' "${rout}" 2>/dev/null || true)"
  rm -f "${rout}"
  if [[ "${rcode}" == "200" && "${restored}" == *Lovelace* ]]; then
    echo "PASS restore-after-scale session=${session}"
  else
    echo "FAIL restore-after-scale http=${rcode} text=${restored:0:160}"
    exit 1
  fi
fi
