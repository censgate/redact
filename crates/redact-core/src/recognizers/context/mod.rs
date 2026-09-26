// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Context keywords grouped by concept, for every shipped locale.
//!
//! A concept matches when any of its terms appears. The boost is
//! `matched concepts / concepts on the pattern × 0.3`, so adding a
//! translation does not dilute an English hit. Every shipped locale is
//! applied on every request. Matching stays a substring search, which is
//! what English scores were built on.

mod en;
mod es;
mod vi;
mod zh;

use std::collections::HashMap;
use std::sync::OnceLock;

use unicode_normalization::{char::canonical_combining_class, UnicodeNormalization};

use crate::types::EntityType;

/// One context idea, shared by every locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Concept {
    Nhs,
    Patient,
    Health,
    Address,
    Mail,
    Ship,
    Passport,
    Travel,
    Medical,
    Hospital,
    Years,
    Old,
    Age,
    Driver,
    License,
    Dl,
    Dmv,
    StateDepartment,
    Account,
    Bank,
    Routing,
    Checking,
    Savings,
    Hmpo,
    Company,
    CompaniesHouse,
    Registration,
    Crn,
    Physician,
    Doctor,
    Nurse,
    Wallet,
    Crypto,
    Coin,
}

/// Every concept. Locales must supply at least one term for each.
#[cfg_attr(not(test), allow(dead_code))]
pub const ALL: &[Concept] = &[
    Concept::Nhs,
    Concept::Patient,
    Concept::Health,
    Concept::Address,
    Concept::Mail,
    Concept::Ship,
    Concept::Passport,
    Concept::Travel,
    Concept::Medical,
    Concept::Hospital,
    Concept::Years,
    Concept::Old,
    Concept::Age,
    Concept::Driver,
    Concept::License,
    Concept::Dl,
    Concept::Dmv,
    Concept::StateDepartment,
    Concept::Account,
    Concept::Bank,
    Concept::Routing,
    Concept::Checking,
    Concept::Savings,
    Concept::Hmpo,
    Concept::Company,
    Concept::CompaniesHouse,
    Concept::Registration,
    Concept::Crn,
    Concept::Physician,
    Concept::Doctor,
    Concept::Nurse,
    Concept::Wallet,
    Concept::Crypto,
    Concept::Coin,
];

/// A pattern a locale adds on top of the English regex.
pub struct ExtraPattern {
    pub entity: EntityType,
    pub regex: &'static str,
    pub score: f32,
    pub concepts: &'static [Concept],
}

/// Positive and negative sentences a locale must satisfy.
#[cfg_attr(not(test), allow(dead_code))]
pub struct Fixture {
    pub text: &'static str,
    pub entity: EntityType,
    /// `true` when the entity must be detected.
    pub expect: bool,
}

struct Locale {
    #[cfg_attr(not(test), allow(dead_code))]
    id: &'static str,
    terms: &'static [(Concept, &'static [&'static str])],
    extras: fn() -> Vec<ExtraPattern>,
    #[cfg_attr(not(test), allow(dead_code))]
    fixtures: &'static [Fixture],
}

fn locales() -> &'static [Locale] {
    &[
        Locale {
            id: "en",
            terms: en::TERMS,
            extras: en::extras,
            fixtures: en::FIXTURES,
        },
        Locale {
            id: "vi",
            terms: vi::TERMS,
            extras: vi::extras,
            fixtures: vi::FIXTURES,
        },
        Locale {
            id: "es",
            terms: es::TERMS,
            extras: es::extras,
            fixtures: es::FIXTURES,
        },
        Locale {
            id: "zh",
            terms: zh::TERMS,
            extras: zh::extras,
            fixtures: zh::FIXTURES,
        },
    ]
}

/// NFC then lowercase. ASCII lowercase is unchanged.
pub fn normalize(text: &str) -> String {
    if text.is_ascii() {
        text.to_lowercase()
    } else {
        text.nfc().collect::<String>().to_lowercase()
    }
}

/// Normalized terms for a concept, from every shipped locale.
pub fn terms_for(concept: Concept) -> &'static [String] {
    static MAP: OnceLock<HashMap<Concept, Vec<String>>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut map: HashMap<Concept, Vec<String>> = HashMap::new();
        for locale in locales() {
            for (concept, terms) in locale.terms {
                let bucket = map.entry(*concept).or_default();
                for term in *terms {
                    let normalized = normalize(term);
                    if !bucket.contains(&normalized) {
                        bucket.push(normalized);
                    }
                }
            }
        }
        map
    })
    .get(&concept)
    .map(Vec::as_slice)
    .unwrap_or(&[])
}

/// Locale regexes compiled into the pattern recognizer.
pub fn extra_patterns() -> Vec<ExtraPattern> {
    locales()
        .iter()
        .flat_map(|locale| (locale.extras)())
        .collect()
}

/// `(locale id, fixture)` for the conformance test.
#[cfg(test)]
pub(crate) fn locale_fixtures() -> Vec<(&'static str, &'static Fixture)> {
    locales()
        .iter()
        .flat_map(|locale| {
            locale
                .fixtures
                .iter()
                .map(move |fixture| (locale.id, fixture))
        })
        .collect()
}

pub(crate) use en::{
    AGE_CONCEPTS, CRYPTO_CONCEPTS, MEDICAL_LICENSE_CONCEPTS, MRN_CONCEPTS, PASSPORT_CONCEPTS,
    PO_BOX_CONCEPTS, UK_COMPANY_CONCEPTS, UK_NHS_CONCEPTS, UK_PASSPORT_CONCEPTS, US_BANK_CONCEPTS,
    US_DRIVER_CONCEPTS, US_PASSPORT_CONCEPTS,
};

/// NFC form of `original` plus the original byte index of each NFC byte.
///
/// Combining marks stay attached to the preceding starter, so a regex match
/// on the NFC string can be mapped back onto the caller's text.
pub fn nfc_with_map(original: &str) -> (String, Vec<usize>) {
    let mut out = String::new();
    let mut map = Vec::new();
    let mut chars = original.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        let mut chunk = String::new();
        chunk.push(ch);
        while let Some((_, next)) = chars.peek().copied() {
            if canonical_combining_class(next) != 0 {
                chunk.push(next);
                chars.next();
            } else {
                break;
            }
        }
        let nfc_chunk: String = chunk.nfc().collect();
        map.extend(std::iter::repeat_n(idx, nfc_chunk.len()));
        out.push_str(&nfc_chunk);
    }
    (out, map)
}

/// Map a match on the NFC string back to `original`.
pub fn map_span(map: &[usize], original_len: usize, start: usize, end: usize) -> (usize, usize) {
    if map.is_empty() || start >= map.len() {
        return (0, 0);
    }
    let orig_start = map[start];
    let orig_end = if end >= map.len() {
        original_len
    } else {
        map[end]
    };
    (orig_start, orig_end.max(orig_start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concept_list_is_exhaustive() {
        let mut seen = vec![false; ALL.len()];
        for concept in ALL {
            let index = match concept {
                Concept::Nhs => 0,
                Concept::Patient => 1,
                Concept::Health => 2,
                Concept::Address => 3,
                Concept::Mail => 4,
                Concept::Ship => 5,
                Concept::Passport => 6,
                Concept::Travel => 7,
                Concept::Medical => 8,
                Concept::Hospital => 9,
                Concept::Years => 10,
                Concept::Old => 11,
                Concept::Age => 12,
                Concept::Driver => 13,
                Concept::License => 14,
                Concept::Dl => 15,
                Concept::Dmv => 16,
                Concept::StateDepartment => 17,
                Concept::Account => 18,
                Concept::Bank => 19,
                Concept::Routing => 20,
                Concept::Checking => 21,
                Concept::Savings => 22,
                Concept::Hmpo => 23,
                Concept::Company => 24,
                Concept::CompaniesHouse => 25,
                Concept::Registration => 26,
                Concept::Crn => 27,
                Concept::Physician => 28,
                Concept::Doctor => 29,
                Concept::Nurse => 30,
                Concept::Wallet => 31,
                Concept::Crypto => 32,
                Concept::Coin => 33,
            };
            assert!(index < seen.len(), "{concept:?} is missing from ALL");
            assert!(!seen[index], "duplicate {concept:?}");
            seen[index] = true;
        }
        assert!(seen.iter().all(|present| *present));
    }

    #[test]
    fn every_locale_covers_every_concept_with_real_terms() {
        for locale in locales() {
            for concept in ALL {
                let terms: Vec<_> = locale
                    .terms
                    .iter()
                    .filter(|(id, _)| id == concept)
                    .flat_map(|(_, terms)| *terms)
                    .collect();
                assert!(
                    !terms.is_empty(),
                    "locale {} is missing {concept:?}",
                    locale.id
                );
                for term in terms {
                    assert!(!term.is_empty(), "{} {:?}", locale.id, concept);
                    if locale.id != "en" && term.is_ascii() {
                        assert!(
                            term.chars().count() >= 4,
                            "locale {} term {term:?} for {concept:?} is shorter than 4",
                            locale.id
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn nfc_map_round_trips_decomposed_vietnamese() {
        let original = "o\u{301} ngân";
        let (nfc, map) = nfc_with_map(original);
        assert_eq!(nfc, "ó ngân");
        let start = nfc.find('ó').unwrap();
        let (orig_start, orig_end) = map_span(&map, original.len(), start, start + 'ó'.len_utf8());
        assert_eq!(&original[orig_start..orig_end], "o\u{301}");
    }

    #[test]
    fn shipped_locales_are_the_reference_set() {
        let ids: Vec<_> = locales().iter().map(|locale| locale.id).collect();
        assert_eq!(ids, ["en", "vi", "es", "zh"]);
    }
}
