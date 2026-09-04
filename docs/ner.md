# ML-powered NER

Optional ONNX Runtime integration for transformer-based named entity
recognition (`PERSON`, `ORGANIZATION`, `LOCATION`). The compiled pattern
engine (61 types) does not require NER.

**DATE_TIME is not a NER product.** The default CoNLL model has no date
labels. `IdentityRecognizer` drops any NER `DATE_TIME` span — pattern packs
own ISO / slash dates. Do not enable a DATE-capable NER to chase “next
Friday” or “January 15”; those are high-FP. See [entity types](entity-types.md).

## Export a HuggingFace model

```bash
pip install transformers optimum[exporters]
python scripts/export_ner_model.py \
    --model dslim/bert-base-NER \
    --output models/bert-base-ner
```

`--quantize` runs dynamic INT8 via `onnxruntime.quantization`. It can move
logits across the 0.7 confidence floor. Do not ship an INT8 graph without a
CoNLL PER/ORG/LOC F1 floor versus the FP32 export.

Required files for inference: `model.onnx` and `tokenizer.json`.

## Use with the engine

```rust
use redact_ner::{NerRecognizer, NerConfig};
use redact_core::AnalyzerEngine;
use std::sync::Arc;

let config = NerConfig {
    model_path: "models/bert-base-ner/model.onnx".to_string(),
    tokenizer_path: Some("models/bert-base-ner/tokenizer.json".to_string()),
    min_confidence: 0.7,
    ..Default::default()
};

let ner = NerRecognizer::from_config(config)?;
let mut engine = AnalyzerEngine::new();
engine.recognizer_registry_mut().add_recognizer(Arc::new(ner));
```

## Serving path (same weights)

When the ONNX `input_ids` sequence dim is dynamic, pad to buckets
`32 / 64 / 128 / 256 / 512` instead of always 512. A bounded session pool
(`CENSGATE_NER_SESSION_POOL`, default 2, cap 4) plus
`CENSGATE_NER_INTRA_THREADS` (default 1) should satisfy
`pool × intra ≈` Guaranteed pod CPUs. Gateway analyze runs on the tokio
blocking pool (`block_in_place` / `spawn_blocking`).

## Recommended models

| Model | Size | Use case |
|-------|------|----------|
| `dslim/bert-base-NER` | ~420MB | **Default.** Image `NER_MODEL`. Do not swap without the gate below. |
| `dslim/distilbert-NER` | ~250MB | Faster same-task candidate. **Gated.** See below. |
| `dbmdz/bert-large-cased-finetuned-conll03-english` | ~1.2GB | Highest accuracy, slower |
| `Davlan/distilbert-base-multilingual-cased-ner-hrl` | ~500MB | Multilingual |

Models must use a CoNLL-2003-style BIO scheme (`B-PER`, `I-PER`, `B-ORG`,
`I-ORG`, `B-LOC`, `I-LOC`). DistilBERT exports omit `token_type_ids`; the
recognizer detects that at load.

The published `ghcr.io/censgate/redact:full` image bakes in
`dslim/bert-base-NER`. See [install](install.md).

## Gated DistilBERT swap

`dslim/distilbert-NER` (66M, Apache-2.0, published F1 ~0.922) is already
loadable. Headline F1 is **not** feature parity. Distil can match aggregate
F1 and still miss Censgate ORG / single-token names. `id2label` order
differs from bert-base; `from_file` reads `config.json` from the export.

Do **not** change `Dockerfile.ner-base` `ARG NER_MODEL` until
[`scripts/validate-distilbert-ner.sh`](../scripts/validate-distilbert-ner.sh)
records:

1. CoNLL-2003 entity-level PER/ORG/LOC F1 within ~0.5–1 pt of bert-base
2. The three prose fixtures in `crates/redact-ner/tests/ner_e2e.rs`
3. A before/after [`scripts/bench-gateway-ner.sh`](../scripts/bench-gateway-ner.sh)

```bash
python scripts/export_ner_model.py \
    --model dslim/distilbert-NER \
    --output models/distilbert-ner
export CENSGATE_NER_MODEL_PATH=$PWD/models/distilbert-ner/model.onnx
./scripts/validate-distilbert-ner.sh
```
