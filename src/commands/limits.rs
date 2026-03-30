use colored::Colorize;

use crate::client::MlabClient;

struct LimitInfo {
    label: &'static str,
    icon: &'static str,
    path: &'static str,
}

const LIMITS: &[LimitInfo] = &[
    LimitInfo { label: "Domain scans", icon: "🌐", path: "/limit/domain" },
    LimitInfo { label: "IP lookups",   icon: "🔍", path: "/limit/ip" },
    LimitInfo { label: "File scans",   icon: "📄", path: "/limit/file" },
];

fn fetch_limit(client: &MlabClient, path: &str) -> Option<u64> {
    client
        .get(path)
        .ok()
        .and_then(|r| r.text().ok())
        .and_then(|t| t.trim().parse().ok())
}

fn print_bar(remaining: u64) -> String {
    let max_width = 20;
    // We don't know the max, so show an absolute bar capped at a reasonable scale
    let fill = (remaining as usize).min(max_width);
    let empty = max_width.saturating_sub(fill);
    format!("{}{}",
        "█".repeat(fill).green(),
        "░".repeat(empty).dimmed(),
    )
}

pub fn run(client: &MlabClient, scan_type: Option<&str>, raw: bool) {
    let targets: Vec<&LimitInfo> = match scan_type {
        Some(t) => {
            let info = LIMITS.iter().find(|l| l.path.ends_with(t));
            match info {
                Some(l) => vec![l],
                None => {
                    eprintln!("Unknown limit type: {t}. Use: domain, ip, or file.");
                    std::process::exit(1);
                }
            }
        }
        None => LIMITS.iter().collect(),
    };

    for limit in &targets {
        match fetch_limit(client, limit.path) {
            Some(remaining) => {
                if raw {
                    println!("{remaining}");
                } else {
                    println!(
                        "  {} {:<14} {} {}",
                        limit.icon,
                        limit.label,
                        print_bar(remaining),
                        format!("{remaining} remaining").bold(),
                    );
                }
            }
            None => {
                if raw {
                    println!("error");
                } else {
                    eprintln!("  {} {:<14} {}", limit.icon, limit.label, "failed to fetch".red());
                }
            }
        }
    }
}
