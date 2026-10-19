//! Similar stored key names for a missing one, so an agent can retry without
//! listing every key. Works on names only; values are never read.

/// Name parts too common to relate two keys on their own.
const GENERIC: &[&str] = &[
    "API", "KEY", "KEYS", "TOKEN", "SECRET", "ACCESS", "ID", "PASSWORD", "PAT", "URL", "PRIVATE",
    "PUBLIC", "CLIENT", "AUTH",
];

fn levenshtein(a: &str, b: &str) -> usize {
    let b = b.as_bytes();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.bytes().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitute = diagonal + usize::from(ca != *cb);
            diagonal = row[j + 1];
            row[j + 1] = substitute.min(row[j] + 1).min(diagonal + 1);
        }
    }
    row[b.len()]
}

fn shares_token(a: &str, b: &str) -> bool {
    a.split('_')
        .filter(|t| t.len() >= 3 && !GENERIC.contains(t))
        .any(|t| b.split('_').any(|u| u == t))
}

/// Up to `limit` stored names close to `target`, nearest first.
pub fn names(target: &str, stored: &[String], limit: usize) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = stored
        .iter()
        .filter(|name| name.as_str() != target)
        .filter_map(|name| {
            let distance = levenshtein(target, name);
            let close = distance <= (target.len().max(name.len()) / 3).max(2);
            let contains =
                target.len() >= 3 && (name.contains(target) || target.contains(name.as_str()));
            (close || contains || shares_token(target, name)).then_some((distance, name))
        })
        .collect();
    scored.sort();
    scored
        .into_iter()
        .take(limit)
        .map(|(_, name)| name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn ranks_typos_and_partial_names_first() {
        let keys = stored(&[
            "OPENAI_API_KEY",
            "OPENAI_ORG_ID",
            "ANTHROPIC_API_KEY",
            "STRIPE_SECRET_KEY",
            "GITHUB_TOKEN",
        ]);
        assert_eq!(
            names("OPENAI_KEY", &keys, 5),
            ["OPENAI_API_KEY", "OPENAI_ORG_ID"]
        );
        assert_eq!(names("ANTHROPIC_APIKEY", &keys, 5), ["ANTHROPIC_API_KEY"]);
        assert_eq!(names("STRIPE_KEY", &keys, 1), ["STRIPE_SECRET_KEY"]);
    }

    #[test]
    fn generic_parts_alone_are_not_similar() {
        let keys = stored(&["GITHUB_TOKEN", "SLACK_BOT_TOKEN"]);
        assert!(names("MAPBOX_ACCESS_TOKEN", &keys, 5).is_empty());
        assert!(names("ANYTHING", &[], 5).is_empty());
    }

    #[test]
    fn edit_distance_is_exact() {
        assert_eq!(levenshtein("KITTEN", "SITTING"), 3);
        assert_eq!(levenshtein("", "ABC"), 3);
        assert_eq!(levenshtein("SAME", "SAME"), 0);
    }
}
