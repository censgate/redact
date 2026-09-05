#!/usr/bin/env bash
# Gated DistilBERT check. Does **not** change Dockerfile.ner-base NER_MODEL.
#
# Headline F1 (dslim/distilbert-NER ~0.922 vs bert-base-NER ~0.913–0.926) is
# not feature parity. Gate a default swap on:
#   1. CoNLL-2003 entity-level PER/ORG/LOC F1 within ~0.5–1 pt of bert-base
#   2. The three prose fixtures in crates/redact-ner/tests/ner_e2e.rs
#   3. A before/after run of scripts/bench-gateway-ner.sh
#
# Usage:
#   CENSGATE_NER_MODEL_PATH=/path/to/distilbert/model.onnx \
#   CONLL_EVAL=1 CONLL_F1_BERT=0.92 CONLL_F1_DISTIL=0.91 \
#   ./scripts/validate-distilbert-ner.sh
set -euo pipefail

echo "DistilBERT validation (gated — default remains dslim/bert-base-NER)"
echo

if [[ -z "${CENSGATE_NER_MODEL_PATH:-}" ]]; then
  echo "FAIL: CENSGATE_NER_MODEL_PATH is required (does not change the image default)." >&2
  echo "  python scripts/export_ner_model.py --model dslim/distilbert-NER --output models/distilbert-ner" >&2
  echo "  export CENSGATE_NER_MODEL_PATH=\$PWD/models/distilbert-ner/model.onnx" >&2
  exit 1
fi

if [[ ! -f "${CENSGATE_NER_MODEL_PATH}" ]]; then
  echo "FAIL: CENSGATE_NER_MODEL_PATH=${CENSGATE_NER_MODEL_PATH} is not a file" >&2
  exit 1
fi

echo "==> e2e fixtures against the supplied model (fails if the model does not load)"
cargo test --package redact-ner --test ner_e2e --test-threads=1 \
  test_ner_honors_censgate_ner_model_path -- --nocapture

echo
echo "==> identity golden (ONNX cases skip only when the path is unset — path is set)"
cargo test --package redact-ner --test identity_golden -- --nocapture

if [[ "${CONLL_EVAL:-}" == "1" ]]; then
  echo
  echo "==> CoNLL-2003 PER/ORG/LOC F1 (operator-recorded; not automated in-repo yet)"
  : "${CONLL_F1_BERT:?set CONLL_F1_BERT to measured entity-level F1 for bert-base-NER}"
  : "${CONLL_F1_DISTIL:?set CONLL_F1_DISTIL to measured entity-level F1 for distilbert-NER}"
  python3 - <<'PY'
import os
import sys
bert = float(os.environ["CONLL_F1_BERT"])
distil = float(os.environ["CONLL_F1_DISTIL"])
# Plan floor: Distil within ~1 pt of bert-base on entity-level PER/ORG/LOC.
if distil + 0.01 < bert:
    print(f"FAIL: Distil F1 {distil} is more than 1 pt below bert-base {bert}", file=sys.stderr)
    sys.exit(1)
print(f"PASS: Distil F1 {distil} is within 1 pt of bert-base {bert}")
PY
else
  echo
  echo "CONLL_EVAL is not 1. Record entity-level F1 before changing NER_MODEL."
  echo "A green fixture run is not permission to swap Dockerfile.ner-base."
fi

echo
echo "Default image model is still dslim/bert-base-NER."
