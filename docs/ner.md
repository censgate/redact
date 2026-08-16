# ML-powered NER

Optional ONNX Runtime integration for transformer-based named entity
recognition (`PERSON`, `ORGANIZATION`, `LOCATION`, contextual `DATE_TIME`).
The compiled pattern engine (61 types) does not require NER.

## Export a HuggingFace model

```bash
pip install transformers optimum[exporters]
python scripts/export_ner_model.py \
    --model dslim/bert-base-NER \
    --output models/bert-base-ner
```

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

## Recommended models

| Model | Size | Use Case |
|-------|------|----------|
| `dslim/bert-base-NER` | ~420MB | Default accuracy/size balance |
| `dbmdz/bert-large-cased-finetuned-conll03-english` | ~1.2GB | Highest accuracy |
| `Davlan/distilbert-base-multilingual-cased-ner-hrl` | ~500MB | Multilingual |
| `elastic/distilbert-base-cased-finetuned-conll03-english` | ~250MB | Smaller/faster |

Models must use a CoNLL-2003-style BIO scheme (`B-PER`, `I-PER`, `B-ORG`, `I-ORG`, `B-LOC`, `I-LOC`).

The published `ghcr.io/censgate/redact:full` image bakes in `dslim/bert-base-NER`.
See [install](install.md).
