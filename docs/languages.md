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

Japanese is not shipped. The NER model list is separate and still does not
include Vietnamese.

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

## Review checklist

- A native speaker has read the terms and the fixtures.
- No new Latin term is a substring of an English term or of a common English word.
- `english_bank_sentence_keeps_a_single_span_at_the_historical_score` still passes.
- Positive fixtures detect. Negative fixtures do not.
- NFD input still detects, not only the precomposed form.
