# SPIKE: NER models for Spanish, simplified Chinese, and Vietnamese

Phase 2 keyword locales for `es`, `zh`, and `vi` are in this branch.
This spike picks the NER weights that can run the existing ONNX path,
records what those weights actually tagged, and decides whether NER is
language-agnostic configuration or a per-language code change.

Pattern detection does not use these models. The default image model
stays `dslim/bert-base-NER` (English, MIT). Nothing here changes that
image.

How to add another language: [Languages](languages.md).

## What the loader already accepts

`scripts/export_ner_model.py` writes `model.onnx`, `tokenizer.json`, and
`config.json`. `NerRecognizer::from_file` reads `id2label` from that
config. A label is kept when the type after `B-` / `I-` is `PER`,
`PERSON`, `ORG`, `ORGANIZATION`, `LOC`, `LOCATION`, or `GPE`. `DATE` and
`TIME` map to `DateTime`. `MISC` is dropped.

`NerConfig::default()` hard-codes a different order (`B-PER` at id 1).
Davlan puts `B-DATE` at id 1. Loading Davlan with the default config
mis-tags every span. Verification must use `from_file`.

The ONNX session already accepts BERT inputs (`input_ids`,
`attention_mask`, `token_type_ids`) and DistilBERT inputs (no
`token_type_ids`). The decoder does not contain a language branch.
`NerRecognizer::analyze` ignores the language argument.

The engine does not. `ner_model_supports_language` is a compiled list:
`en es fr de it pt nl pl ru zh ja ko`. `vi` is not on it, so
`AnalyzerEngine` skips NER for Vietnamese even when the loaded file
would have tagged the text. `es` and `zh` are on it even when the loaded
file is the English image model.

## Models

Checked against the Hugging Face config and file list on 2026-09-26.

| Model | License | Labels the loader maps | ONNX in the repo | Role |
| --- | --- | --- | --- | --- |
| `Davlan/bert-base-multilingual-cased-ner-hrl` | AFL-3.0 | `PER` `ORG` `LOC` `DATE` | Yes: `onnx/model.onnx` (677MB), `onnx/tokenizer.json`, `onnx/config.json`. Inputs are the three BERT tensors. | **Run this for e2e.** Trained on Spanish (CoNLL-2002) and simplified Chinese (MSRA), plus ar, de, en, fr, it, lv, nl, pt. Not trained on Vietnamese. |
| `Davlan/distilbert-base-multilingual-cased-ner-hrl` | AFL-3.0 | Same card | No `tokenizer.json` or `onnx/`. Export with the script. Checkpoint is ~540MB fp32. | Same languages, smaller architecture. Not executed here. |
| `shibing624/bert4ner-base-chinese` | Apache-2.0 | `PER` `ORG` `LOC` `TIME` | No. `BertTokenizer`, raw characters, simplified Chinese. | Use if a Chinese organization splits under Davlan. Not executed. |
| `undertheseanlp/vietnamese-ner-v1.4.0a2` | Apache-2.0 | `PER` `ORG` `LOC` `MISC` | No. Has `tokenizer.json`. Vocab starts with syllables (`có`, `là`), not underscore words. | Vietnamese-trained candidate when Davlan transfer is not enough. Export first. Not executed. |
| `dslim/bert-base-NER` | MIT | CoNLL English | Image default | Unchanged. Does not cover these three languages. |

Rejected:

| Model | Why it is not an e2e candidate |
| --- | --- |
| `NlpHUST/ner-vietnamese-electra-base` | Labels map (`PERSON`, `ORGANIZATION`, `LOCATION`) and `tokenizer.json` exists, but the card has no license. Do not vendor it. |
| PhoBERT NER (`vinai/phobert-base` and fine-tunes) | Raw text must be word-segmented with VnCoreNLP first. The recognizer tokenizes the original string. |
| `Babelscape/wikineural-multilingual-ner` | CC-BY-NC-SA-4.0. Covers Spanish, not Chinese or Vietnamese. |
| `mrm8488/bert-spanish-cased-finetuned-ner` | Labels map, no license on the card. Davlan already covers Spanish. |
| `MinhMinh09/multilingual-bert-base-cased-vietnamese-finetuned-ner` | `id2label` is `LABEL_0` … `LABEL_4`. The loader would drop every tag. |
| GLiNER (`fastino/gliner2-multi-v1` and ONNX rebuilds) | Span scores, not BIO. Needs a new decoder. |

AFL-3.0 weights stay operator-supplied. Do not copy them into the
Apache-2.0 image and do not change `ARG NER_MODEL`.

## What was executed

ONNX Runtime 1.30.0 and `tokenizers` 0.23.2, CPU, the published Davlan
bert `onnx/` files. Pad length 64. A span is reported below when every
token's softmax peaked on a mapped label at 0.7 or above. The Rust
decoder averages those probabilities instead of taking the minimum; the
two failures below are boundary errors, so the average would not hide
them.

The same directory was then loaded with `NerRecognizer::from_file`
(`ort` 2.0.0-rc.12 against that `libonnxruntime.so.1.30.0`).
`test_reference_language_ner_smoke` passed. The recognizer leaves
`RecognizerResult.text` empty, so the test slices `text[start..end]`.
That covers the English sentence, both Spanish sentences, the `腾讯` and
`阿里巴巴` sentences, and the `FPT` / `Vietcombank` Vietnamese sentences.

| Text | Spans at 0.7 |
| --- | --- |
| `John Doe works at Microsoft in Seattle.` | PERSON `John Doe`, ORG `Microsoft`, LOC `Seattle` |
| `María García trabaja en Telefónica en Madrid.` | PERSON `María García`, ORG `Telefónica`, LOC `Madrid` |
| `Pedro Sánchez visitó Barcelona y habló con Iberdrola.` | PERSON `Pedro Sánchez`, LOC `Barcelona`, ORG `Iberdrola` |
| `张伟就职于腾讯，住在深圳。` | PERSON `张伟`, ORG `腾讯`, LOC `深圳` |
| `李明在北京大学学习。` | PERSON `李明`, ORG `北京大学` |
| `马云创立了阿里巴巴，总部位于杭州。` | PERSON `马云`, ORG `阿里巴巴`, LOC `杭州` |
| `Nguyễn Văn An làm việc tại FPT ở Hà Nội.` | PERSON `Nguyễn Văn An`, ORG `FPT`, LOC `Hà Nội` |
| `Trần Thị Mai làm việc tại Vietcombank ở Thành phố Hồ Chí Minh.` | PERSON `Trần Thị Mai`, ORG `Vietcombank`, LOC `Thành phố Hồ Chí Minh` |
| `Phạm Minh Chính đến thăm Tập đoàn Vingroup tại Hà Nội.` | PERSON `Phạm Minh Chính`, ORG `Tập đoàn Vingroup`, LOC `Hà Nội` |
| `Nguyễn Văn An sống ở Đà Nẵng.` | PERSON `Nguyễn Văn An`, LOC `Đà Nẵng` |

Failures, same run:

| Text | What the model did |
| --- | --- |
| `王伟在北京的华为工作。` | PERSON `王伟`, LOC `北京`, then `华为` split. `华` was an organization below 0.7 and `为` was PERSON at 0.703. The org is missing and a false person remains. |
| `Ông Lê Văn Tám công tác tại Đại học Bách khoa Hà Nội.` | PERSON `Lê Văn Tám`. The organization span stopped at `Đại học Bách khoa Hà` and dropped ` Nội`. |

Those two sentences are not in `test_reference_language_ner_smoke`. The
sentences that matched are. Re-run:

```bash
export REDACT_NER_SMOKE_DIR=/path/to/davlan-onnx   # model.onnx beside tokenizer.json and config.json
export ORT_DYLIB_PATH=/path/to/libonnxruntime.so
cargo test -p redact-ner --test ner_e2e -- --ignored test_reference_language_ner_smoke
```

Vietnamese rows are transfer. The model card does not list `vi`. Six
hand-picked sentences are not an F1 score. Do not describe the image, or
this branch, as having Vietnamese NER.

`shibing624/bert4ner-base-chinese` is the Apache-2.0 model to export when
a simplified-Chinese organization splits the way `华为` did.
`undertheseanlp/vietnamese-ner-v1.4.0a2` is the Apache-2.0 model to export
when a Vietnamese span truncates or is missed. Neither was loaded in
this spike. Both match the label and raw-text rules above, so the same
smoke test can take their export directory.

## Determination

Keyword phase 2 is already language-agnostic code. Contributors configure
a language by adding `context/<code>.rs` and registering it in
`locales()`. The matcher applies every registered locale on every
request. Latin terms shorter than 4 characters are rejected; CJK terms
are not. That is a script rule, not a language switch. A runtime pack
format is not required for the next language.

NER is language-agnostic only up to the file format. Any mainstream
language with a BIO model of the shape above can be verified by changing
the configured NER model path or `REDACT_NER_SMOKE_DIR`. No decoder fork.

NER is not configurable per request language. The allowlist is compiled
in and does not follow the file. Shipping a multi-model router (Davlan
for `es`/`zh`, a second file for `vi`) would be new code and is not
justified by this spike: one published ONNX file already smoke-tested
all three languages, with the two misses above. A second file replaces
the first; it does not sit beside it.

Do not add `vi` to `ner_model_supports_language` in this branch. The
image model would then run on Vietnamese requests and the allowlist
would claim support the weights do not have. Do not remove `es` or `zh`
either: that changes which requests reach whatever model an operator
already configured.

The follow-up that would make the NER gate match the keyword design is a
language list on the export `config.json`, defaulting to today's match
list when the key is absent. An operator who loads Davlan would set the
codes that file was trained on. That is a config field, not a new public
API and not a per-language recognizer. It is out of scope for this
spike.
