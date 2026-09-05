//! Output format selection, resolved once at startup.
//!
//! `--json` on a sub-command still works and still wins; `--output` is the
//! uniform switch. CSV is only offered where a command has a genuine tabular
//! shape — inventing rows for a nested report would produce something worse
//! than useless in a spreadsheet, so those commands say so instead.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::error::{ApiError, ErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    Csv,
}

static FORMAT: AtomicU8 = AtomicU8::new(0);

pub fn init(format: Option<&str>) {
    let value = match format
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => 1,
        Some("csv") => 2,
        _ => 0,
    };
    FORMAT.store(value, Ordering::SeqCst);
}

pub fn format() -> Format {
    match FORMAT.load(Ordering::SeqCst) {
        1 => Format::Json,
        2 => Format::Csv,
        _ => Format::Table,
    }
}

/// `--json` is a per-command shorthand that predates `--output`; both are honoured.
pub fn wants_json(local_flag: bool) -> bool {
    local_flag || format() == Format::Json
}

pub fn wants_csv() -> bool {
    format() == Format::Csv
}

/// Called by commands that have no meaningful CSV shape.
pub fn refuse_csv(command: &str) -> ! {
    ApiError {
        status: None,
        message: format!("{command} has no CSV form — use --output json."),
        kind: ErrorKind::Input,
    }
    .report()
}

/// Escape one field per RFC 4180.
pub fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

pub fn csv_row(fields: &[String]) -> String {
    fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",")
}

/// Print a CSV table with its header.
pub fn csv_table(header: &[&str], rows: &[Vec<String>]) {
    println!(
        "{}",
        header
            .iter()
            .map(|h| csv_field(h))
            .collect::<Vec<_>>()
            .join(",")
    );
    for row in rows {
        println!("{}", csv_row(row));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_or_missing_format_falls_back_to_the_table() {
        init(None);
        assert_eq!(format(), Format::Table);
        init(Some("banana"));
        assert_eq!(format(), Format::Table);
    }

    #[test]
    fn formats_parse_case_insensitively() {
        init(Some("JSON"));
        assert_eq!(format(), Format::Json);
        init(Some(" csv "));
        assert_eq!(format(), Format::Csv);
        init(None);
    }

    #[test]
    fn a_local_json_flag_wins_over_the_global_default() {
        init(None);
        assert!(wants_json(true));
        assert!(!wants_json(false));
        init(Some("json"));
        assert!(wants_json(false));
        init(None);
    }

    #[test]
    fn fields_are_quoted_only_when_they_have_to_be() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("with,comma"), "\"with,comma\"");
        assert_eq!(csv_field("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(csv_field("with\nnewline"), "\"with\nnewline\"");
    }

    #[test]
    fn a_row_joins_escaped_fields() {
        let row = csv_row(&["a".into(), "b,c".into(), "d\"e".into()]);
        assert_eq!(row, "a,\"b,c\",\"d\"\"e\"");
    }

    #[test]
    fn a_formula_like_cell_is_still_quoted_when_it_contains_a_separator() {
        // Not sanitisation — just the escaping the format requires.
        assert_eq!(csv_field("=SUM(A1,A2)"), "\"=SUM(A1,A2)\"");
    }
}
