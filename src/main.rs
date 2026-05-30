mod client;
mod commands;
mod config;

use clap::{Parser, Subcommand};

use client::MlabClient;
use config::Config;

#[derive(Parser)]
#[command(name = "mlab", version, about = "CLI client for the mlab.sh threat intelligence API")]
struct Cli {
    /// Override the API hostname (default: https://mlab.sh)
    #[arg(long, global = true)]
    hostname: Option<String>,

    /// Override the CVE API hostname (default: https://vuln.mlab.sh)
    #[arg(long, global = true)]
    cve_hostname: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with your API key
    Login,

    /// Test your API connection
    Whoami,

    /// Launch a scan
    Scan {
        #[command(subcommand)]
        target: ScanTarget,
    },

    /// Check scan status
    Status {
        #[command(subcommand)]
        target: StatusTarget,
    },

    /// Retrieve scan results
    Results {
        #[command(subcommand)]
        target: ResultsTarget,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Get SSL certificate info for a domain
    Ssl {
        /// Domain to check
        domain: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },

    /// CVE lookups (vuln.mlab.sh, no auth required)
    Cve {
        #[command(subcommand)]
        action: CveAction,
    },

    /// Check scan quotas
    Limits {
        /// Limit type: domain, ip, file, or crypto (omit to show all)
        #[arg(value_name = "TYPE")]
        scan_type: Option<String>,

        /// Output raw numbers only
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Subcommand)]
enum ScanTarget {
    /// Scan a domain (launches scan, waits for results, and displays them)
    Domain {
        /// Domain to scan (e.g. example.com)
        domain: String,

        /// Don't wait for scan to finish (just launch and exit)
        #[arg(long)]
        no_follow: bool,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Lookup an IP address
    Ip {
        /// IPv4 or IPv6 address
        ip: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Upload and scan a file
    File {
        /// Path to the file
        path: String,
    },
    /// Lookup a cryptocurrency address
    Crypto {
        /// Wallet/contract address
        address: String,

        /// Blockchain (e.g. eth, btc)
        #[arg(long, default_value = "eth")]
        chain: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CveAction {
    /// Search CVEs by keyword
    Search {
        /// Search query
        query: String,

        /// Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        #[arg(long)]
        severity: Option<String>,

        /// Restrict to CVEs published on or after this date (YYYY-MM-DD)
        #[arg(long)]
        date_start: Option<String>,

        /// Exact-match search
        #[arg(long)]
        exact: bool,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Show details for a specific CVE
    Detail {
        /// CVE identifier (e.g. CVE-2024-3094)
        id: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Show CVEs from the past week
    Latest {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum StatusTarget {
    /// Check domain scan status
    Domain {
        /// Domain to check
        domain: String,
    },
}

#[derive(Subcommand)]
enum ResultsTarget {
    /// Get domain scan results
    Domain {
        /// Domain to get results for
        domain: String,
    },
    /// Get file scan results
    File {
        /// SHA256 hash from the upload response
        sha256: String,
    },
}

fn make_client(cli: &Cli) -> MlabClient {
    let config = Config::load();
    let hostname = cli
        .hostname
        .as_deref()
        .unwrap_or(&config.hostname);
    let api_key = config.require_api_key();
    MlabClient::new(hostname, api_key)
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Login => {
            commands::login::run();
        }
        Commands::Whoami => {
            let client = make_client(&cli);
            commands::whoami::run(&client);
        }
        Commands::Scan { target } => {
            let client = make_client(&cli);
            match target {
                ScanTarget::Domain { domain, no_follow, json } => commands::scan::domain(&client, domain, *no_follow, *json),
                ScanTarget::Ip { ip, json } => commands::scan::ip(&client, ip, *json),
                ScanTarget::File { path } => commands::scan::file(&client, path),
                ScanTarget::Crypto { address, chain, json } => commands::scan::crypto(&client, address, chain, *json),
            }
        }
        Commands::Status { target } => {
            let client = make_client(&cli);
            match target {
                StatusTarget::Domain { domain } => commands::status::domain(&client, domain),
            }
        }
        Commands::Results { target, json } => {
            let client = make_client(&cli);
            match target {
                ResultsTarget::Domain { domain } => commands::results::domain(&client, domain, *json),
                ResultsTarget::File { sha256 } => commands::results::file(&client, sha256, *json),
            }
        }
        Commands::Ssl { domain, json } => {
            let client = make_client(&cli);
            commands::ssl::run(&client, domain, *json);
        }
        Commands::Cve { action } => {
            let host = commands::cve::resolve_hostname(cli.cve_hostname.as_deref());
            match action {
                CveAction::Search { query, severity, date_start, exact, json } => {
                    commands::cve::search(&host, query, severity.as_deref(), date_start.as_deref(), *exact, *json);
                }
                CveAction::Detail { id, json } => {
                    commands::cve::detail(&host, id, *json);
                }
                CveAction::Latest { json } => {
                    commands::cve::latest(&host, *json);
                }
            }
        }
        Commands::Limits { scan_type, raw } => {
            let client = make_client(&cli);
            commands::limits::run(&client, scan_type.as_deref(), *raw);
        }
    }
}
