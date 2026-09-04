//! CVSS v3 base-score arithmetic.
//!
//! OSV advisories carry a vector string, not a severity label — so a CI gate has
//! to compute the score itself. This is a direct port of the formula the scan
//! page uses, so `--fail-on high` fails on exactly what the web UI paints red.

/// Severity band. Ordered so thresholds can be compared directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::None => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "crit" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "med" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

/// Band a base score the same way the web UI does.
pub fn band(score: Option<f64>) -> Severity {
    match score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(s) if s > 0.0 => Severity::Low,
        _ => Severity::None,
    }
}

fn metric(params: &[(&str, &str)], key: &str) -> Option<&'static str> {
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .map(|v| match v {
            "N" => "N", "A" => "A", "L" => "L", "P" => "P",
            "H" => "H", "R" => "R", "C" => "C", "U" => "U",
            _ => "?",
        })
}

/// Base score for a `CVSS:3.x/...` vector. `None` for anything else — an
/// unparsable vector must not silently become 0.0, which would read as "clean".
pub fn base_score(vector: &str) -> Option<f64> {
    let upper = vector.trim().to_ascii_uppercase();
    if !upper.starts_with("CVSS:3") {
        return None;
    }

    let params: Vec<(&str, &str)> = upper
        .split('/')
        .skip(1)
        .filter_map(|kv| kv.split_once(':'))
        .collect();

    let scope_changed = metric(&params, "S") == Some("C");

    let av = match metric(&params, "AV")? {
        "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => return None,
    };
    let ac = match metric(&params, "AC")? {
        "L" => 0.77, "H" => 0.44, _ => return None,
    };
    let ui = match metric(&params, "UI")? {
        "N" => 0.85, "R" => 0.62, _ => return None,
    };
    let pr = match metric(&params, "PR")? {
        "N" => 0.85,
        "L" => if scope_changed { 0.68 } else { 0.62 },
        "H" => if scope_changed { 0.5 } else { 0.27 },
        _ => return None,
    };
    let impact_of = |m: &str| match m {
        "H" => Some(0.56), "L" => Some(0.22), "N" => Some(0.0), _ => None,
    };
    let c = impact_of(metric(&params, "C")?)?;
    let i = impact_of(metric(&params, "I")?)?;
    let a = impact_of(metric(&params, "A")?)?;

    let iss: f64 = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact: f64 = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }

    let exploitability: f64 = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };

    // CVSS rounds up to one decimal, never to nearest.
    Some((base * 10.0).ceil() / 10.0)
}

/// Highest CVSS:3 score attached to an OSV vulnerability entry.
pub fn score_of(vuln: &serde_json::Value) -> Option<f64> {
    vuln.get("severity")
        .and_then(|s| s.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("score").and_then(|s| s.as_str()))
        .filter_map(base_score)
        .fold(None, |acc: Option<f64>, s| Some(acc.map_or(s, |a: f64| a.max(s))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_score_as_the_specification_says() {
        // Reference vectors from the CVSS v3.1 examples.
        assert_eq!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), Some(7.5));
        assert_eq!(base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), Some(5.5));
        assert_eq!(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some(6.1));
    }

    #[test]
    fn a_vector_that_is_not_cvss_v3_scores_nothing_rather_than_zero() {
        // Zero would band as "none" and quietly pass a --fail-on gate.
        assert_eq!(base_score(""), None);
        assert_eq!(base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"), None);
        assert_eq!(base_score("CVSS:3.1/AV:N"), None);
        assert_eq!(base_score("nonsense"), None);
    }

    #[test]
    fn bands_match_the_thresholds_the_web_ui_paints() {
        assert_eq!(band(Some(9.8)), Severity::Critical);
        assert_eq!(band(Some(9.0)), Severity::Critical);
        assert_eq!(band(Some(8.9)), Severity::High);
        assert_eq!(band(Some(7.0)), Severity::High);
        assert_eq!(band(Some(6.9)), Severity::Medium);
        assert_eq!(band(Some(4.0)), Severity::Medium);
        assert_eq!(band(Some(3.9)), Severity::Low);
        assert_eq!(band(Some(0.0)), Severity::None);
        assert_eq!(band(None), Severity::None);
    }

    #[test]
    fn severities_order_so_a_threshold_can_be_compared() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::None);
    }

    #[test]
    fn thresholds_parse_from_what_a_user_would_type() {
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
        assert_eq!(Severity::parse("high"), Some(Severity::High));
        assert_eq!(Severity::parse(" moderate "), Some(Severity::Medium));
        assert_eq!(Severity::parse("banana"), None);
    }

    #[test]
    fn the_worst_vector_on_an_advisory_wins() {
        let vuln = serde_json::json!({
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        });
        assert_eq!(score_of(&vuln), Some(9.8));
    }

    #[test]
    fn an_advisory_with_no_usable_vector_has_no_score() {
        assert_eq!(score_of(&serde_json::json!({})), None);
        assert_eq!(score_of(&serde_json::json!({"severity": []})), None);
        assert_eq!(
            score_of(&serde_json::json!({"severity":[{"type":"CVSS_V2","score":"AV:N/AC:L"}]})),
            None
        );
    }
}
