# Languages

Pattern detection runs for every language code. Context keywords are grouped
by concept so a translation cannot dilute an English hit, and every shipped
locale is applied on every request. There is no language detector.

Shipped locales:

| Code | Language | Notes |
|------|----------|--------|
| `en` | English | The historical keyword lists. Scores on ASCII text stay the same. |
| `vi` | Vietnamese | Precomposed, decomposed (NFD), and unaccented spellings. |
| `es` | Spanish | Accents plus an explicit unaccented spelling where it differs. |
| `zh` | Simplified Chinese | Substring match. Chinese is not split on spaces. |

Japanese is not a shipped keyword locale. NER is a separate, optional model.
The default NER image is English. Spanish, simplified Chinese, and a
Vietnamese smoke check have a verification model; they are not NER
languages of that image. See [NER language spike](ner-languages-spike.md).

## Language-agnostic configuration

Keyword matching is language-agnostic code. It does not branch on `vi`,
`es`, or `zh`. Every shipped locale is applied to every request. Adding a
mainstream language is a new table in this crate, not a new matcher and
not a per-request switch. There is no language detector.

NER is one ONNX file per process, chosen with `ner.model_path`
(see the gateway configuration for the environment name). The tokenizer
and BIO decoder are shared. A
model runs without Rust changes when it is a token-classification export
with `tokenizer.json` and BIO labels whose type suffix is `PER`, `PERSON`,
`ORG`, `ORGANIZATION`, `LOC`, `LOCATION`, or `GPE`.

The request-language gate is not that file. `ner_model_supports_language`
is a compiled list. It allows `es` and `zh` even when the loaded weights
are the English image model, and it rejects `vi` even when the loaded
weights tag Vietnamese text. One process cannot load a second model beside
the first. Details and the decision to keep it that way are in the
[spike](ner-languages-spike.md).

## Matching rules

- A concept matches when **any** of its terms appears. The boost is
  `matched concepts / concepts on that pattern × 0.3`.
- Terms are NFC-normalized, then lowercased, then sought as substrings.
  That is the same search English already used. Word-start matching is not
  enabled, because it would change existing English scores.
- Unaccented spellings are written out in the locale file. They are never
  produced by stripping marks.
- Latin terms added by a non-English locale must be at least 4 characters.
  `DL` stays in English only. Short syllables such as `so` or `ma` are
  rejected because they occur inside English words.
- CJK terms may be shorter. They are matched as substrings.

## Add a locale

1. Copy `crates/redact-core/src/recognizers/context/en.rs` to a new file,
   for example `de.rs`.
2. Give every [`Concept`](../crates/redact-core/src/recognizers/context/mod.rs)
   at least one term. The compiler and the conformance test both fail if one
   is missing.
3. Add `Age`, `PoBox`, `MedicalRecordNumber`, and `UsBankNumber` regexes
   whose keywords cannot occur in ordinary English. Keep the English regexes
   where they are.
4. Add positive fixtures (the phrase must be detected) and a negative fixture
   (a bare number must not be).
5. Register the module in `context/mod.rs` `locales()`.
6. Run `cargo test -p redact-core`.

Do not change `Recognizer::supports_language`'s default. NER and third-party
recognizers keep their own lists. Do not change
`PatternRecognizer::add_pattern_with_context`; that method still takes a
`Vec<String>` and treats each string as its own ad-hoc concept, with no
translations.

## Add an NER model

Keyword locales and NER models are separate contributions. A locale file
does not make names, organizations, or places detectable.

1. Choose a Hugging Face token-classification model that reads raw text.
   Reject a model that needs an external word segmenter before the
   tokenizer. PhoBERT is in that category.
2. Read `config.json` `id2label`. The type after `B-` / `I-` must be
   `PER`, `PERSON`, `ORG`, `ORGANIZATION`, `LOC`, `LOCATION`, or `GPE`.
   `MISC` is ignored. `DATE` and `TIME` become `DateTime`, which the
   identity layer drops.
3. Check the license. Apache-2.0 and MIT can be documented for operators.
   Academic Free License and a missing license are local verification
   only. Do not change `Dockerfile.ner-base`.
4. Export, or reuse a published `onnx/` directory that already contains
   `model.onnx`, `tokenizer.json`, and `config.json`:

   ```bash
   python scripts/export_ner_model.py \
       --model ORG/MODEL \
       --output models/my-ner
   ```

5. Load with `NerRecognizer::from_file`. That reads `id2label` from
   `config.json`. `NerConfig::default()` assumes a different label order.
6. Add a sentence to `test_reference_language_ner_smoke` in
   `crates/redact-ner/tests/ner_e2e.rs`, then run:

   ```bash
   export REDACT_NER_SMOKE_DIR=$PWD/models/my-ner
   export ORT_DYLIB_PATH=/path/to/libonnxruntime.so
   cargo test -p redact-ner --test ner_e2e -- --ignored test_reference_language_ner_smoke
   ```

7. Leave `ner_model_supports_language` unchanged unless the model baked
   into the image was trained for the new code. The smoke test calls the
   recognizer directly. `AnalyzerEngine` will still skip a code that is
   not on the list. Putting `vi` on that list while the image model is
   English marks Vietnamese requests as NER-capable when the weights are
   not.

One gateway process serves one NER file. A language outside that file's
training set needs its own export and its own verification command. It
does not need a forked decoder. The current verification file for
Spanish and simplified Chinese is
`Davlan/bert-base-multilingual-cased-ner-hrl`. Vietnamese was not in its
training data; the spike records which smoke sentences transferred and
which ones did not.

## Review checklist

- A native speaker has read the terms and the fixtures.
- No new Latin term is a substring of an English term or of a common English word.
- `english_bank_sentence_keeps_a_single_span_at_the_historical_score` still passes.
- Positive fixtures detect. Negative fixtures do not.
- NFD input still detects, not only the precomposed form.
- An NER model, if you added one, was loaded with `from_file` and the
  smoke sentences match the spans you expect. The default image model
  was not replaced.
