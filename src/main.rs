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

    /// Check scan quotas
    Limits {
        /// Limit type: domain, ip, or file (omit to show all)
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
        Commands::Limits { scan_type, raw } => {
            let client = make_client(&cli);
            commands::limits::run(&client, scan_type.as_deref(), *raw);
        }
    }
}
