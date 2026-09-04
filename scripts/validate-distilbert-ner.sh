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
#   CONLL_EVAL=1 \
#   ./scripts/validate-distilbert-ner.sh
set -euo pipefail

echo "DistilBERT validation (gated — default remains dslim/bert-base-NER)"
echo

if [[ -z "${CENSGATE_NER_MODEL_PATH:-}" ]]; then
  echo "Export first (does not change the image default):"
  echo "  python scripts/export_ner_model.py --model dslim/distilbert-NER --output models/distilbert-ner"
  echo "  export CENSGATE_NER_MODEL_PATH=\$PWD/models/distilbert-ner/model.onnx"
  echo
  echo "Then re-run this script. Do not bump redact-ner-base or NER_MODEL"
  echo "until CoNLL + fixture numbers are recorded below."
  exit 0
fi

echo "==> e2e fixtures (ignored without a model; --ignored with a path)"
cargo test --package redact-ner --test ner_e2e -- --ignored --nocapture

echo
echo "==> identity golden (ONNX cases skip if path unset — path is set)"
cargo test --package redact-ner --test identity_golden -- --nocapture

if [[ "${CONLL_EVAL:-}" == "1" ]]; then
  echo
  echo "==> CoNLL-2003 PER/ORG/LOC F1 is not automated in this repo yet."
  echo "    Record entity-level F1 for bert-base-NER and distilbert-NER on the"
  echo "    same split before changing Dockerfile.ner-base ARG NER_MODEL."
  echo "    Reject the swap if ORG or single-token names regress."
fi

echo
echo "Default image model is still dslim/bert-base-NER."
echo "Do not treat a green fixture run as permission to swap NER_MODEL."
