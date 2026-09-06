// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Identity-context parser: names and places only when surrounding language
//! says they are identity, never from capitalization alone.

use redact_core::{EntityType, RecognizerResult};

const SOURCE: &str = "ContextualIdentity";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Person,
    Location,
}

#[derive(Debug, Clone)]
struct Hit {
    kind: Kind,
    start: usize,
    end: usize,
    score: f32,
}

#[derive(Debug, Clone, Copy)]
struct Token<'a> {
    start: usize,
    end: usize,
    text: &'a str,
}

pub fn detect_contextual_identities(text: &str) -> Vec<RecognizerResult> {
    let tokens = tokenize(text);
    let mut hits: Vec<Hit> = Vec::new();

    collect_greetings(text, &tokens, &mut hits);
    collect_relationships(text, &tokens, &mut hits);
    collect_named_called(text, &tokens, &mut hits);
    collect_pets(text, &tokens, &mut hits);
    collect_role_is_are(text, &tokens, &mut hits);
    collect_name_runs_the(text, &tokens, &mut hits);
    collect_repeated_person_surfaces(text, &tokens, &mut hits);
    collect_locations(text, &tokens, &mut hits);
    collect_metro_areas(text, &tokens, &mut hits);

    let sealed = vault_token_spans(text);
    merge_hits(hits)
        .into_iter()
        .filter(|h| !sealed.iter().any(|(s, e)| h.start < *e && h.end > *s))
        .map(|h| {
            let ty = match h.kind {
                Kind::Person => EntityType::Person,
                Kind::Location => EntityType::Location,
            };
            RecognizerResult::new(ty, h.start, h.end, h.score, SOURCE)
        })
        .collect()
}

/// Spans of already-minted vault tokens such as `[PERSON_1]` or `[EMAIL_ADDRESS_2]`.
pub(crate) fn vault_token_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(rel) = text[i + 1..].find(']') {
                let inner = &text[i + 1..i + 1 + rel];
                if is_vault_token_inner(inner) {
                    let end = i + 1 + rel + 1;
                    out.push((i, end));
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn is_vault_token_inner(inner: &str) -> bool {
    let Some((ty, num)) = inner.rsplit_once('_') else {
        return false;
    };
    !ty.is_empty()
        && ty.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && !num.is_empty()
        && num.chars().all(|c| c.is_ascii_digit())
}

fn tokenize(text: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (i, ch) in text.char_indices() {
        if is_word_char(ch) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            tokens.push(Token {
                start: s,
                end: i,
                text: &text[s..i],
            });
        }
    }
    if let Some(s) = start {
        tokens.push(Token {
            start: s,
            end: text.len(),
            text: &text[s..],
        });
    }
    tokens
}

fn is_word_char(ch: char) -> bool {
    ch.is_alphabetic() || ch == '\'' || ch == '’' || ch == '-'
}

fn collect_greetings(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !is_greeting(tok.text) {
            continue;
        }
        if let Some(name) = tokens.get(i + 1) {
            if accept_name(name.text, NameRule::strong_no_calendar()) {
                push_hit(hits, Kind::Person, name.start, name.end, 0.93);
            }
        }
        let _ = text;
    }
}

fn collect_relationships(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !is_relationship(tok.text) {
            continue;
        }
        if i == 0 || !is_possessor(tokens[i - 1].text) {
            continue;
        }
        if let Some(name) = next_name_after(text, tokens, i, NameRule::strong_with_calendar()) {
            push_hit(hits, Kind::Person, name.start, name.end, 0.94);
        }
    }
}

fn collect_named_called(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        let lower = tok.text.to_ascii_lowercase();
        let name_tok = if matches!(lower.as_str(), "named" | "called") {
            tokens.get(i + 1)
        } else if lower == "name" {
            match tokens.get(i + 1) {
                Some(next)
                    if next.text.eq_ignore_ascii_case("is")
                        || next.text.eq_ignore_ascii_case("s") =>
                {
                    tokens.get(i + 2)
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some(name) = name_tok {
            if accept_name(name.text, NameRule::strong_with_calendar())
                && !is_inside_skip_parens(text, name.start)
            {
                push_hit(hits, Kind::Person, name.start, name.end, 0.94);
            }
        }
    }
}

fn collect_role_is_are(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !is_relationship(tok.text) && !is_role(tok.text) {
            continue;
        }
        let Some(verb) = tokens.get(i + 1) else {
            continue;
        };
        if !verb.text.eq_ignore_ascii_case("is") && !verb.text.eq_ignore_ascii_case("are") {
            continue;
        }
        for name in names_after_verb(text, tokens, i + 2) {
            push_hit(hits, Kind::Person, name.0, name.1, 0.94);
        }
    }
}

fn collect_name_runs_the(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !tok.text.eq_ignore_ascii_case("runs") || i == 0 {
            continue;
        }
        let Some(the) = tokens.get(i + 1) else {
            continue;
        };
        if !the.text.eq_ignore_ascii_case("the") {
            continue;
        }
        let prev = tokens[i - 1];
        if accept_name(prev.text, NameRule::strong_no_calendar())
            && !is_inside_skip_parens(text, prev.start)
        {
            push_hit(hits, Kind::Person, prev.start, prev.end, 0.93);
        }
    }
}

fn collect_repeated_person_surfaces(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    let cores: Vec<String> = hits
        .iter()
        .filter(|h| h.kind == Kind::Person)
        .map(|h| person_core(&text[h.start..h.end]))
        .filter(|c| c.chars().count() >= 2)
        .collect();
    if cores.is_empty() {
        return;
    }
    for tok in tokens {
        if is_inside_skip_parens(text, tok.start) {
            continue;
        }
        let core = person_core(tok.text);
        if cores.iter().any(|c| c.eq_ignore_ascii_case(&core))
            && accept_name(tok.text, NameRule::strong_with_calendar())
        {
            push_hit(hits, Kind::Person, tok.start, tok.end, 0.93);
        }
    }
}

fn person_core(word: &str) -> String {
    let mut s = word.to_string();
    for suffix in ["'s", "’s", "'S", "’S"] {
        if s.len() > suffix.len() && s.ends_with(suffix) {
            s.truncate(s.len() - suffix.len());
            break;
        }
    }
    s
}

fn names_after_verb(text: &str, tokens: &[Token<'_>], start: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = start;
    while i < tokens.len() {
        let tok = tokens[i];
        if i > start {
            let gap = &text[tokens[i - 1].end..tok.start];
            if gap.contains('.') || gap.contains(';') {
                break;
            }
        }
        if tok.text.eq_ignore_ascii_case("and") || tok.text.eq_ignore_ascii_case("or") {
            i += 1;
            continue;
        }
        if !accept_name(tok.text, NameRule::strong_with_calendar()) {
            break;
        }
        if is_inside_skip_parens(text, tok.start) {
            i += 1;
            continue;
        }
        out.push((tok.start, tok.end));
        i += 1;
    }
    out
}

fn is_role(word: &str) -> bool {
    matches!(word.to_ascii_lowercase().as_str(), "mascot" | "mascots")
}

fn collect_pets(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !is_pet(tok.text) {
            continue;
        }
        if colon_after(text, tok.end) {
            for name in names_in_list(text, tok.end) {
                push_hit(hits, Kind::Person, name.0, name.1, 0.95);
            }
            continue;
        }
        let possessed = i > 0 && is_possessor(tokens[i - 1].text);
        if !possessed {
            continue;
        }
        if let Some(name) = next_name_after(text, tokens, i, NameRule::strong_with_calendar()) {
            push_hit(hits, Kind::Person, name.start, name.end, 0.95);
        }
    }
}

fn collect_locations(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !tok.text.eq_ignore_ascii_case("in") && !tok.text.eq_ignore_ascii_case("from") {
            continue;
        }
        if !has_location_verb_before(tokens, i) {
            continue;
        }
        for span in location_phrase(text, tokens, i + 1) {
            push_hit(hits, Kind::Location, span.0, span.1, 0.93);
        }
    }
}

fn collect_metro_areas(text: &str, tokens: &[Token<'_>], hits: &mut Vec<Hit>) {
    for (i, tok) in tokens.iter().enumerate() {
        if !tok.text.eq_ignore_ascii_case("metro") {
            continue;
        }
        let Some(area) = tokens.get(i + 1) else {
            continue;
        };
        if !area.text.eq_ignore_ascii_case("area") {
            continue;
        }
        let Some(name) = tokens.get(i.saturating_sub(1)).filter(|_| i > 0) else {
            continue;
        };
        if accept_name(name.text, NameRule::strong_no_calendar()) {
            push_hit(hits, Kind::Location, name.start, name.end, 0.92);
        }
        let _ = text;
    }
}

fn has_location_verb_before(tokens: &[Token<'_>], in_idx: usize) -> bool {
    let start = in_idx.saturating_sub(4);
    tokens[start..in_idx]
        .iter()
        .any(|t| is_location_verb(t.text))
}

fn location_phrase(text: &str, tokens: &[Token<'_>], start: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = start;
    while i < tokens.len() {
        let tok = tokens[i];
        if is_stop_after_location(tok.text) {
            break;
        }
        if tok.text.eq_ignore_ascii_case("metro") || tok.text.eq_ignore_ascii_case("area") {
            i += 1;
            continue;
        }
        if !accept_name(tok.text, NameRule::strong_no_calendar()) {
            // Parenthetical place: "( Riverton metro area )"
            if text.get(tok.start.saturating_sub(2)..tok.start).is_some() {
                i += 1;
                continue;
            }
            break;
        }
        let mut end = tok.end;
        let span_start = tok.start;
        let mut j = i + 1;
        while j < tokens.len() {
            let nxt = tokens[j];
            if between_is_space_only(text, end, nxt.start)
                && accept_name(nxt.text, NameRule::strong_no_calendar())
                && !nxt.text.eq_ignore_ascii_case("metro")
                && !nxt.text.eq_ignore_ascii_case("area")
            {
                end = nxt.end;
                j += 1;
                continue;
            }
            break;
        }
        out.push((span_start, end));
        i = j;
        // comma-separated next place is allowed; other punctuation stops
        if i < tokens.len() {
            let gap = &text[end..tokens[i].start];
            if gap.contains('.') || gap.contains(';') {
                break;
            }
            if !gap.contains(',') && !gap.contains('(') && !gap.chars().all(|c| c.is_whitespace()) {
                // leftover words like "I" after the phrase
                if is_stop_after_location(tokens[i].text) {
                    break;
                }
            }
        }
    }
    out
}

fn between_is_space_only(text: &str, start: usize, end: usize) -> bool {
    text.get(start..end)
        .is_some_and(|g| !g.is_empty() && g.chars().all(|c| c.is_whitespace()))
}

fn next_name_after<'a>(
    text: &str,
    tokens: &'a [Token<'a>],
    after_idx: usize,
    rule: NameRule,
) -> Option<Token<'a>> {
    let name = tokens.get(after_idx + 1)?;
    if is_inside_skip_parens(text, name.start) {
        return None;
    }
    if accept_name(name.text, rule) {
        Some(*name)
    } else {
        None
    }
}

fn names_in_list(text: &str, after_pet_end: usize) -> Vec<(usize, usize)> {
    let Some(colon) = text[after_pet_end..].find(':') else {
        return Vec::new();
    };
    let mut idx = after_pet_end + colon + 1;
    let mut out = Vec::new();
    while idx < text.len() {
        idx = skip_ws(text, idx);
        if idx >= text.len() {
            break;
        }
        if text[idx..].starts_with('(') {
            idx = skip_parens(text, idx);
            continue;
        }
        let rest = &text[idx..];
        if rest.is_empty() {
            break;
        }
        let ch = rest.chars().next().unwrap();
        if !ch.is_alphabetic() {
            if ch == '.' || ch == ';' {
                break;
            }
            idx += ch.len_utf8();
            continue;
        }
        let token_end = rest
            .char_indices()
            .find(|(_, c)| !is_word_char(*c))
            .map(|(i, _)| idx + i)
            .unwrap_or(text.len());
        let word = &text[idx..token_end];
        if word.eq_ignore_ascii_case("and") || word.eq_ignore_ascii_case("or") {
            idx = token_end;
            continue;
        }
        if !accept_name(word, NameRule::strong_with_calendar()) {
            break;
        }
        out.push((idx, token_end));
        idx = token_end;
        idx = skip_ws(text, idx);
        if text[idx..].starts_with('(') {
            idx = skip_parens(text, idx);
        }
    }
    out
}

fn colon_after(text: &str, end: usize) -> bool {
    let rest = text[end..].trim_start();
    rest.starts_with(':')
}

fn skip_ws(text: &str, mut idx: usize) -> usize {
    while idx < text.len() {
        let ch = text[idx..].chars().next().unwrap();
        if !ch.is_whitespace() {
            break;
        }
        idx += ch.len_utf8();
    }
    idx
}

fn skip_parens(text: &str, start: usize) -> usize {
    if !text[start..].starts_with('(') {
        return start;
    }
    let mut depth = 0;
    for (i, ch) in text[start..].char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                return start + i + 1;
            }
        }
    }
    text.len()
}

fn is_inside_skip_parens(text: &str, pos: usize) -> bool {
    let mut depth = 0;
    for (i, ch) in text.char_indices() {
        if i >= pos {
            return depth > 0;
        }
        if ch == '(' {
            depth += 1;
        } else if ch == ')' && depth > 0 {
            depth -= 1;
        }
    }
    false
}

fn push_hit(hits: &mut Vec<Hit>, kind: Kind, start: usize, end: usize, score: f32) {
    if start >= end {
        return;
    }
    hits.push(Hit {
        kind,
        start,
        end,
        score,
    });
}

fn merge_hits(mut hits: Vec<Hit>) -> Vec<Hit> {
    hits.sort_by_key(|h| (h.start, h.end));
    let mut out: Vec<Hit> = Vec::new();
    for hit in hits {
        if let Some(prev) = out.last_mut() {
            if hit.start < prev.end {
                // Overlap: explicit kind already stored wins; extend span if needed.
                if hit.kind == prev.kind {
                    prev.end = prev.end.max(hit.end);
                    prev.score = prev.score.max(hit.score);
                }
                continue;
            }
        }
        out.push(hit);
    }
    out
}

#[derive(Clone, Copy)]
struct NameRule {
    allow_calendar: bool,
}

impl NameRule {
    fn strong_with_calendar() -> Self {
        Self {
            allow_calendar: true,
        }
    }
    fn strong_no_calendar() -> Self {
        Self {
            allow_calendar: false,
        }
    }
}

fn accept_name(word: &str, rule: NameRule) -> bool {
    if word.chars().count() < 2 {
        return false;
    }
    if is_function_word(word) || is_name_keyword(word) || is_common_non_name(word) {
        return false;
    }
    if is_calendar(word) && !rule.allow_calendar {
        return false;
    }
    word.chars()
        .all(|c| c.is_alphabetic() || c == '\'' || c == '’' || c == '-')
}

fn is_greeting(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "hi" | "hello" | "hey" | "dear" | "hiya"
    )
}

fn is_possessor(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "my" | "our" | "his" | "her" | "their" | "a" | "an" | "the"
    )
}

fn is_relationship(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "wife"
            | "husband"
            | "daughter"
            | "son"
            | "mother"
            | "father"
            | "sister"
            | "brother"
            | "friend"
            | "partner"
            | "colleague"
            | "child"
            | "children"
            | "kid"
            | "kids"
            | "parent"
            | "parents"
            | "mom"
            | "dad"
            | "mum"
            | "mommy"
            | "mummy"
            | "aunt"
            | "uncle"
            | "niece"
            | "nephew"
            | "cousin"
            | "grandmother"
            | "grandfather"
            | "grandma"
            | "grandpa"
            | "spouse"
            | "girlfriend"
            | "boyfriend"
            | "roommate"
            | "neighbor"
            | "neighbors"
            | "neighbour"
            | "neighbours"
            | "boss"
            | "teacher"
            | "student"
            | "doctor"
            | "lawyer"
            | "client"
            | "customer"
            | "fiance"
            | "fiancee"
            | "fiancé"
            | "fiancée"
    )
}

fn is_pet(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "cat"
            | "cats"
            | "dog"
            | "dogs"
            | "puppy"
            | "puppies"
            | "kitten"
            | "kittens"
            | "pet"
            | "pets"
            | "horse"
            | "horses"
            | "bird"
            | "birds"
            | "fish"
            | "hamster"
            | "hamsters"
            | "rabbit"
            | "rabbits"
            | "gerbil"
            | "ferret"
            | "parrot"
            | "pony"
            | "goldfish"
    )
}

fn is_location_verb(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "live"
            | "lives"
            | "lived"
            | "living"
            | "based"
            | "located"
            | "stay"
            | "staying"
            | "stayed"
            | "moved"
            | "moving"
            | "reside"
            | "resides"
            | "residing"
            | "relocated"
    )
}

fn is_stop_after_location(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "i" | "we"
            | "you"
            | "they"
            | "he"
            | "she"
            | "it"
            | "and"
            | "but"
            | "the"
            | "a"
            | "an"
            | "my"
            | "our"
            | "with"
            | "where"
            | "when"
            | "who"
    )
}

fn is_name_keyword(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "named" | "called" | "name" | "names" | "call"
    )
}

fn is_function_word(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "the"
            | "a"
            | "an"
            | "and"
            | "or"
            | "of"
            | "in"
            | "on"
            | "at"
            | "to"
            | "for"
            | "with"
            | "from"
            | "by"
            | "as"
            | "is"
            | "was"
            | "are"
            | "were"
            | "be"
            | "been"
            | "this"
            | "that"
            | "these"
            | "those"
            | "it"
            | "we"
            | "you"
            | "they"
            | "he"
            | "she"
            | "i"
            | "my"
            | "our"
            | "their"
            | "his"
            | "her"
            | "me"
            | "us"
            | "them"
            | "there"
            | "here"
            | "now"
            | "then"
            | "back"
            | "all"
            | "day"
            | "earlier"
            | "later"
            | "today"
            | "tomorrow"
            | "yesterday"
    )
}

/// Ordinary English that identity cues must not treat as a name or place.
fn is_common_non_name(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "person"
            | "location"
            | "organization"
            | "email"
            | "address"
            | "starts"
            | "start"
            | "started"
            | "starting"
            | "school"
            | "schools"
            | "constant"
            | "fear"
            | "fears"
            | "loud"
            | "quiet"
            | "quietly"
            | "always"
            | "never"
            | "still"
            | "also"
            | "very"
            | "just"
            | "only"
            | "even"
            | "really"
            | "about"
            | "into"
            | "over"
            | "under"
            | "after"
            | "before"
            | "because"
            | "while"
            | "though"
            | "although"
            | "unless"
            | "until"
            | "since"
            | "during"
            | "without"
            | "within"
            | "between"
            | "through"
            | "across"
            | "around"
            | "against"
            | "along"
            | "behind"
            | "go"
            | "goes"
            | "going"
            | "went"
            | "come"
            | "comes"
            | "coming"
            | "came"
            | "get"
            | "gets"
            | "getting"
            | "got"
            | "make"
            | "makes"
            | "made"
            | "take"
            | "takes"
            | "took"
            | "see"
            | "sees"
            | "saw"
            | "know"
            | "knows"
            | "think"
            | "thinks"
            | "want"
            | "wants"
            | "need"
            | "needs"
            | "work"
            | "works"
            | "working"
            | "play"
            | "plays"
            | "sleep"
            | "sleeps"
            | "sleeping"
            | "love"
            | "loves"
            | "loved"
            | "loving"
            | "like"
            | "likes"
            | "liked"
            | "eat"
            | "eats"
            | "eating"
            | "ate"
            | "peace"
            | "happy"
            | "sad"
            | "angry"
    )
}

fn is_calendar(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "monday"
            | "tuesday"
            | "wednesday"
            | "thursday"
            | "friday"
            | "saturday"
            | "sunday"
            | "mondays"
            | "tuesdays"
            | "wednesdays"
            | "thursdays"
            | "fridays"
            | "saturdays"
            | "sundays"
            | "january"
            | "february"
            | "march"
            | "april"
            | "may"
            | "june"
            | "july"
            | "august"
            | "september"
            | "october"
            | "november"
            | "december"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_keeps_offsets() {
        let text = "Hi Ada";
        let toks = tokenize(text);
        assert_eq!(toks[0].text, "Hi");
        assert_eq!(toks[1].text, "Ada");
        assert_eq!(&text[toks[1].start..toks[1].end], "Ada");
    }
}
