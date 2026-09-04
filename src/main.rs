mod client;
mod commands;
mod config;
mod cvss;
mod error;
mod ui;
mod util;

use clap::{Parser, Subcommand};

use client::{MlabClient, HostClient};
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

    /// Use this API key instead of the stored one (or $MLAB_API_KEY)
    #[arg(long, global = true, value_name = "KEY")]
    api_key: Option<String>,

    /// Override the threat-actor API hostname (default: https://actors.mlab.sh)
    #[arg(long, global = true)]
    actors_hostname: Option<String>,

    /// Personal vuln.mlab.sh token (or $MLAB_VULN_TOKEN) — raises the scan quota
    #[arg(long, global = true, value_name = "TOKEN")]
    vuln_token: Option<String>,

    /// Suppress spinners and progress output
    #[arg(long, short, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with your API key
    Login {
        /// Provide the key non-interactively (useful in CI)
        #[arg(long, value_name = "KEY")]
        key: Option<String>,
    },

    /// Forget the stored API key
    Logout,

    /// Test your API connection
    Whoami {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Launch a scan
    Scan {
        #[command(subcommand)]
        target: ScanTarget,
    },

    /// Check scan status
    Status {
        #[command(subcommand)]
        target: StatusTarget,

        /// Output raw JSON
        #[arg(long, global = true)]
        json: bool,
    },

    /// Retrieve scan results
    Results {
        #[command(subcommand)]
        target: ResultsTarget,

        /// Output raw JSON
        ///
        /// Global within `results` so it is accepted both before and after the
        /// sub-command, matching how `scan ... --json` reads.
        #[arg(long, global = true)]
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

    /// Extract indicators of compromise from text
    Ioc {
        /// File to read, or `-` for stdin
        #[arg(default_value = "-")]
        source: String,

        /// Country pack for smishing keywords (e.g. fr, uk)
        #[arg(long)]
        country: Option<String>,

        /// Risk scoring: fast (local) or deep (network)
        #[arg(long, value_parser = ["fast", "deep"])]
        risk: Option<String>,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Capture the network requests a page makes
    Network {
        /// URL to load
        url: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },

    /// Scan a dependency manifest for known vulnerabilities
    Sbom {
        #[command(subcommand)]
        action: SbomAction,
    },

    /// Package-scoped vulnerability queries (OSV-compatible)
    Vuln {
        #[command(subcommand)]
        action: VulnAction,
    },

    /// Threat actor intelligence (actors.mlab.sh, no auth required)
    Actor {
        #[command(subcommand)]
        action: ActorAction,
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

        /// Wait for the analysis to finish and print the report
        #[arg(long)]
        follow: bool,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Lookup one or more cryptocurrency addresses
    Crypto {
        /// Wallet/contract addresses (more than one switches to the bulk endpoint)
        #[arg(required = true)]
        addresses: Vec<String>,

        /// Blockchain (e.g. eth, btc). Omit to let the API detect it from the address.
        #[arg(long)]
        chain: Option<String>,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Analyse a URL (structure, host reputation, optional redirect chain)
    Url {
        /// URL to analyse
        url: String,

        /// Follow the link to resolve redirects (off by default: it fetches the target)
        #[arg(long)]
        resolve: bool,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Look up one or more file hashes (SHA-1, SHA-256, MD5)
    Hash {
        /// Digests (more than one switches to the bulk endpoint)
        #[arg(required = true)]
        hashes: Vec<String>,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Look up an email address
    Email {
        /// Address to inspect
        email: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Look up a phone number
    Phone {
        /// Number, ideally in E.164 form (+33...)
        number: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Look up a MAC address
    Mac {
        /// MAC address in any common notation
        mac: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Analyse a shell script for suspicious patterns and indicators
    Bash {
        /// Path to the script, or `-` for stdin
        path: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
}

/// The filter set `/api/v1/cve`, `/export/csv` and `/rss` all read.
#[derive(clap::Args, Clone)]
struct CveFilters {
    /// Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
    #[arg(long)]
    severity: Option<String>,

    /// Restrict to CVEs published on or after this date (YYYY-MM-DD)
    #[arg(long)]
    date_start: Option<String>,

    /// Restrict to CVEs published on or before this date (YYYY-MM-DD)
    #[arg(long)]
    date_end: Option<String>,

    /// Narrow to a vendor (merged into the keyword server-side)
    #[arg(long)]
    vendor: Option<String>,

    /// Filter by weakness, e.g. CWE-79
    #[arg(long)]
    cwe: Option<String>,

    /// Only CVEs scoring at least this CVSS value (0-10)
    #[arg(long)]
    min_cvss: Option<f64>,

    /// Only CVEs listed in the CISA KEV catalogue
    #[arg(long)]
    kev_only: bool,

    /// Exact-match search
    #[arg(long)]
    exact: bool,
}

impl CveFilters {
    fn as_options(&self, page: u32, limit: Option<u32>) -> commands::cve::SearchOptions<'_> {
        commands::cve::SearchOptions {
            severity: self.severity.as_deref(),
            date_start: self.date_start.as_deref(),
            date_end: self.date_end.as_deref(),
            vendor: self.vendor.as_deref(),
            cwe: self.cwe.as_deref(),
            min_cvss: self.min_cvss,
            kev_only: self.kev_only,
            exact: self.exact,
            page,
            limit,
        }
    }
}

#[derive(Subcommand)]
enum CveAction {
    /// Search CVEs by keyword
    Search {
        /// Search query
        query: String,

        #[command(flatten)]
        filters: CveFilters,

        /// Result page, starting at 0
        #[arg(long, default_value_t = 0)]
        page: u32,

        /// Results per page (max 100)
        #[arg(long)]
        limit: Option<u32>,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Export search results as CSV or an RSS feed
    Export {
        /// Search query
        #[arg(default_value = "")]
        query: String,

        #[command(flatten)]
        filters: CveFilters,

        /// Output format
        #[arg(long, default_value = "csv", value_parser = ["csv", "rss"])]
        format: String,
    },
    /// Download a bulk CVE extract (rate limited per IP)
    Dump {
        /// Published on or after this date (YYYY-MM-DD)
        #[arg(long)]
        date_start: Option<String>,

        /// Published on or before this date (YYYY-MM-DD)
        #[arg(long)]
        date_end: Option<String>,

        /// Only CVEs scoring at least this CVSS value
        #[arg(long)]
        min_cvss: Option<f64>,
    },
    /// Database statistics
    Stats {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Advisory sources being ingested
    Sources {
        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// National advisories, optionally for one CVE
    Advisories {
        /// Restrict to a CVE identifier
        #[arg(long)]
        cve: Option<String>,

        /// Restrict to a country code
        #[arg(long)]
        country: Option<String>,

        /// Maximum rows
        #[arg(long)]
        limit: Option<u32>,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Per-month CVE counts for a vendor
    Vendor {
        /// Vendor name
        vendor: String,

        /// Year to chart
        #[arg(long)]
        year: u32,

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
enum ActorAction {
    /// List actors
    List {
        /// Suspected country of origin (the API calls this `origin`)
        #[arg(long, alias = "country")]
        origin: Option<String>,

        /// Filter by motivation, e.g. "Information theft and espionage"
        #[arg(long)]
        motivation: Option<String>,

        /// Filter by targeted sector
        #[arg(long)]
        sector: Option<String>,

        /// Only actors changed since this ISO timestamp
        #[arg(long)]
        updated_since: Option<String>,

        /// Page size (max 500)
        #[arg(long)]
        limit: Option<u32>,

        /// Page offset
        #[arg(long, default_value_t = 0)]
        offset: u32,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Show one actor by slug
    Get {
        /// Actor slug, e.g. apt28
        slug: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// Which actors are documented exploiting a CVE
    ByCve {
        /// CVE identifier
        cve: String,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
    /// STIX 2.1 bundle for one actor
    Stix {
        /// Actor slug
        slug: String,
    },
    /// Bulk export of every actor
    Export {
        /// Output format
        #[arg(long, default_value = "csv", value_parser = ["csv", "jsonl"])]
        format: String,
    },
}

#[derive(Subcommand)]
enum SbomAction {
    /// Scan a lockfile (path, `-` for stdin, or --url)
    Scan {
        /// Lockfile to scan, or `-` to read stdin
        path: Option<String>,

        /// Scan a lockfile published at this URL instead
        #[arg(long, conflicts_with = "path")]
        url: Option<String>,

        /// Force the manifest format instead of detecting it (npm, cargo, …)
        #[arg(long)]
        format: Option<String>,

        /// Exit 7 when a finding reaches this severity
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,

        /// Output raw JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum VulnAction {
    /// Look up one package coordinate (purl, or ecosystem/name)
    Query {
        /// e.g. pkg:cargo/time or crates.io/time
        coordinate: String,

        /// Package version
        #[arg(long)]
        version: Option<String>,

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

        /// Print one tool's raw output instead of the summary
        #[arg(long, value_name = "NAME")]
        tool: Option<String>,
    },
}

fn make_actors_client(cli: &Cli) -> HostClient {
    let config = Config::load();
    let hostname = config.resolved_actors_hostname(cli.actors_hostname.as_deref());
    // Public, read-only host: no credential to pass.
    HostClient::new(&hostname, None)
}

fn make_vuln_client(cli: &Cli) -> HostClient {
    let config = Config::load();
    let hostname = config.resolved_cve_hostname(cli.cve_hostname.as_deref());
    let token = config.resolved_vuln_token(cli.vuln_token.as_deref());
    HostClient::new(&hostname, token)
}

fn make_client(cli: &Cli) -> MlabClient {
    let config = Config::load();
    let hostname = config.resolved_hostname(cli.hostname.as_deref());
    let api_key = config.resolved_api_key(cli.api_key.as_deref());
    MlabClient::new(&hostname, &api_key)
}

fn main() {
    let cli = Cli::parse();
    ui::init(cli.quiet);

    match &cli.command {
        Commands::Login { key } => {
            let config = Config::load();
            let hostname = config.resolved_hostname(cli.hostname.as_deref());
            commands::login::run(&hostname, key.as_deref());
        }
        Commands::Logout => {
            commands::login::logout();
        }
        Commands::Whoami { json } => {
            let client = make_client(&cli);
            commands::whoami::run(&client, *json);
        }
        Commands::Scan { target } => {
            let client = make_client(&cli);
            match target {
                ScanTarget::Domain { domain, no_follow, json } => commands::scan::domain(&client, domain, *no_follow, *json),
                ScanTarget::Ip { ip, json } => commands::scan::ip(&client, ip, *json),
                ScanTarget::File { path, follow, json } => commands::scan::file(&client, path, *follow, *json),
                ScanTarget::Crypto { addresses, chain, json } => commands::scan::crypto(&client, addresses, chain.as_deref(), *json),
                ScanTarget::Url { url, resolve, json } => commands::lookup::url(&client, url, *resolve, *json),
                ScanTarget::Hash { hashes, json } => commands::lookup::hash(&client, hashes, *json),
                ScanTarget::Email { email, json } => commands::lookup::email(&client, email, *json),
                ScanTarget::Phone { number, json } => commands::lookup::phone(&client, number, *json),
                ScanTarget::Mac { mac, json } => commands::lookup::mac(&client, mac, *json),
                ScanTarget::Bash { path, json } => commands::lookup::bash(&client, path, *json),
            }
        }
        Commands::Status { target, json } => {
            let client = make_client(&cli);
            match target {
                StatusTarget::Domain { domain } => commands::status::domain(&client, domain, *json),
            }
        }
        Commands::Results { target, json } => {
            let client = make_client(&cli);
            match target {
                ResultsTarget::Domain { domain } => commands::results::domain(&client, domain, *json),
                ResultsTarget::File { sha256, tool } => {
                    commands::results::file(&client, sha256, tool.as_deref(), *json)
                }
            }
        }
        Commands::Ioc { source, country, risk, json } => {
            let client = make_client(&cli);
            commands::lookup::ioc(&client, source, country.as_deref(), risk.as_deref(), *json);
        }
        Commands::Network { url, json } => {
            let client = make_client(&cli);
            commands::lookup::network(&client, url, *json);
        }
        Commands::Ssl { domain, json } => {
            let client = make_client(&cli);
            commands::ssl::run(&client, domain, *json);
        }
        Commands::Cve { action } => {
            let client = make_vuln_client(&cli);
            match action {
                CveAction::Search { query, filters, page, limit, json } => {
                    commands::cve::search(&client, query, &filters.as_options(*page, *limit), *json);
                }
                CveAction::Export { query, filters, format } => {
                    commands::cve::export(&client, query, &filters.as_options(0, None), format);
                }
                CveAction::Dump { date_start, date_end, min_cvss } => {
                    commands::cve::dump(&client, date_start.as_deref(), date_end.as_deref(), *min_cvss);
                }
                CveAction::Stats { json } => commands::cve::stats(&client, *json),
                CveAction::Sources { json } => commands::cve::sources(&client, *json),
                CveAction::Advisories { cve, country, limit, json } => {
                    commands::cve::advisories(&client, cve.as_deref(), country.as_deref(), *limit, *json);
                }
                CveAction::Vendor { vendor, year, json } => {
                    commands::cve::vendor_months(&client, vendor, *year, *json);
                }
                CveAction::Detail { id, json } => commands::cve::detail(&client, id, *json),
                CveAction::Latest { json } => commands::cve::latest(&client, *json),
            }
        }
        Commands::Actor { action } => {
            let client = make_actors_client(&cli);
            match action {
                ActorAction::List { origin, motivation, sector, updated_since, limit, offset, json } => {
                    let filters = commands::actor::ListFilters {
                        origin: origin.as_deref(),
                        motivation: motivation.as_deref(),
                        sector: sector.as_deref(),
                        updated_since: updated_since.as_deref(),
                        limit: *limit,
                        offset: *offset,
                    };
                    commands::actor::list(&client, &filters, *json);
                }
                ActorAction::Get { slug, json } => commands::actor::get(&client, slug, *json),
                ActorAction::ByCve { cve, json } => {
                    let cve = commands::actor::validate_cve(cve);
                    commands::actor::by_cve(&client, &cve, *json);
                }
                ActorAction::Stix { slug } => commands::actor::stix(&client, slug),
                ActorAction::Export { format } => commands::actor::export(&client, format),
            }
        }
        Commands::Sbom { action } => {
            let client = make_vuln_client(&cli);
            match action {
                SbomAction::Scan { path, url, format, fail_on, json } => {
                    let opts = commands::vuln::ScanOptions {
                        source: path.as_deref(),
                        url: url.as_deref(),
                        format: format.as_deref(),
                        fail_on: fail_on.as_deref(),
                        json: *json,
                    };
                    commands::vuln::scan(&client, &opts);
                }
            }
        }
        Commands::Vuln { action } => {
            let client = make_vuln_client(&cli);
            match action {
                VulnAction::Query { coordinate, version, json } => {
                    commands::vuln::query(&client, coordinate, version.as_deref(), *json);
                }
            }
        }
        Commands::Limits { scan_type, raw } => {
            let client = make_client(&cli);
            commands::limits::run(&client, scan_type.as_deref(), *raw);
        }
    }
}
