//! `mlab module` — the out-of-tree `mlab-*` binaries.
//!
//! A module is a separate repository that ships its own `mlab-<name>` binary on
//! GitHub releases. Nothing is linked into the core: we find the binary and exec
//! it, so `mlab unifi devices` behaves exactly like running `mlab-unifi devices`
//! by hand, down to the exit code and the module's own `--help`.
//!
//! The catalogue is `modules.json` at the root of this repository, read over
//! raw.githubusercontent.com. Publishing a module is then a commit here and no
//! core release. A copy is compiled in as the offline fallback.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{ApiError, ErrorKind};
use crate::ui;

const CATALOG_URL: &str = "https://raw.githubusercontent.com/mlab-sh/mlab-cli/main/modules.json";

/// Compiled in so `module available` and a mistyped sub-command still say
/// something useful with no network.
const BUILTIN_CATALOG: &str = include_str!("../../modules.json");

/// How long a fetched catalogue stays good: long enough that back-to-back
/// commands do not each hit GitHub, short enough that a module published today
/// is installable today.
const CATALOG_TTL: Duration = Duration::from_secs(6 * 3600);

// ---------------------------------------------------------------------------
// Catalogue
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub modules: Vec<CatalogEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogEntry {
    pub name: String,
    pub binary: String,
    pub repo: String,
    #[serde(default)]
    pub description: String,
    /// Target triples with a published release asset. A host outside this list
    /// can still install with `--from-source`.
    #[serde(default)]
    pub targets: Vec<String>,
    /// Asset filename template. `{binary}`, `{version}` and `{target}` are
    /// substituted; defaults to the layout every mlab release workflow emits.
    #[serde(default)]
    pub asset: Option<String>,
}

impl Catalog {
    fn find(&self, name: &str) -> Option<&CatalogEntry> {
        self.modules.iter().find(|m| m.name == name)
    }
}

impl CatalogEntry {
    fn asset_name(&self, version: &str, target: &str) -> String {
        self.asset
            .as_deref()
            .unwrap_or("{binary}-{version}-{target}.tar.gz")
            .replace("{binary}", &self.binary)
            .replace("{version}", version)
            .replace("{target}", target)
    }

    /// `owner/repo`, for the GitHub API.
    fn slug(&self) -> String {
        self.repo
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .rsplit("github.com/")
            .next()
            .unwrap_or(&self.repo)
            .to_string()
    }
}

fn parse_catalog(raw: &str) -> Option<Catalog> {
    serde_json::from_str(raw).ok()
}

/// The catalogue, preferring a fresh copy but never failing: a network outage
/// degrades to the cached or compiled-in list rather than breaking `mlab`.
pub fn load_catalog(refresh: bool) -> Catalog {
    let cache = Config::dir().join("catalog.json");

    if !refresh {
        if let Some(catalog) = fresh_cache(&cache).and_then(|raw| parse_catalog(&raw)) {
            return catalog;
        }
    }

    if let Ok(raw) = get_text(CATALOG_URL) {
        if let Some(catalog) = parse_catalog(&raw) {
            let _ = fs::create_dir_all(Config::dir());
            let _ = fs::write(&cache, &raw);
            return catalog;
        }
    }

    // Fetch failed or served something unparseable: a stale cache still beats
    // a list frozen at whenever this binary was built.
    fs::read_to_string(&cache)
        .ok()
        .and_then(|raw| parse_catalog(&raw))
        .or_else(|| parse_catalog(BUILTIN_CATALOG))
        .unwrap_or_default()
}

/// The catalogue without touching the network. A mistyped command has to stay
/// instant: making `mlab scna` wait on GitHub to tell you it meant `scan` is
/// worse than suggesting from a slightly stale list.
fn offline_catalog() -> Catalog {
    fs::read_to_string(Config::dir().join("catalog.json"))
        .ok()
        .and_then(|raw| parse_catalog(&raw))
        .or_else(|| parse_catalog(BUILTIN_CATALOG))
        .unwrap_or_default()
}

fn fresh_cache(path: &Path) -> Option<String> {
    let age = fs::metadata(path).ok()?.modified().ok()?.elapsed().ok()?;
    (age < CATALOG_TTL).then(|| fs::read_to_string(path).ok())?
}

// ---------------------------------------------------------------------------
// Local registry
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub modules: BTreeMap<String, Installed>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Installed {
    pub version: String,
    pub binary: String,
    pub repo: String,
    /// `release` for a downloaded asset, `source` for a local cargo build.
    pub source: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub installed_at: u64,
}

impl Registry {
    fn path() -> PathBuf {
        Config::dir().join("modules.json")
    }

    pub fn load() -> Self {
        fs::read_to_string(Self::path())
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        let _ = fs::create_dir_all(Config::dir());
        if let Ok(raw) = serde_json::to_string_pretty(self) {
            let _ = fs::write(Self::path(), raw);
        }
    }
}

pub fn bin_dir() -> PathBuf {
    Config::dir().join("bin")
}

pub fn sources_dir() -> PathBuf {
    Config::dir().join("sources")
}

// ---------------------------------------------------------------------------
// Resolution and dispatch
// ---------------------------------------------------------------------------

/// A module name is a bare lowercase word. Rejecting anything else is what
/// keeps `mlab ../../../bin/sh` from ever resolving to a path.
fn is_module_name(name: &str) -> bool {
    !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `~/.mlab/bin` first, then the PATH — so a module installed with Homebrew
/// (`brew install mlab-sh/tap/mlab-unifi`) works without `mlab module install`.
pub fn resolve(name: &str) -> Option<PathBuf> {
    if !is_module_name(name) {
        return None;
    }
    let binary = format!("mlab-{name}");
    let local = bin_dir().join(&binary);
    if is_executable(&local) {
        return Some(local);
    }
    which(&binary)
}

fn which(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Everything clap did not recognise lands here. Either a module owns it, or
/// nothing does and we say so with the closest name we can find.
pub fn dispatch(args: &[OsString], profile: Option<&str>) -> ! {
    let Some(first) = args.first() else {
        ApiError::new(None, "no command given — try `mlab --help`.").report();
    };
    let name = first.to_string_lossy().to_string();

    match resolve(&name) {
        Some(binary) => exec(&binary, &args[1..], profile),
        None => unknown(&name),
    }
}

fn exec(binary: &Path, args: &[OsString], profile: Option<&str>) -> ! {
    let mut command = Command::new(binary);
    command.args(args);

    // The core's global flags are consumed before the module name, so they never
    // reach the module as flags. The profile is the one piece of shared state
    // worth forwarding, and the environment is where every mlab binary already
    // looks for it.
    if let Some(profile) = profile {
        command.env(crate::config::PROFILE_ENV, profile);
    }
    command.env("MLAB_CORE_VERSION", env!("CARGO_PKG_VERSION"));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Replace this process rather than wrapping it: exit codes, Ctrl-C, job
        // control and the module's own TTY detection then behave exactly as if
        // the user had run the module binary directly. `exec` only returns on
        // failure.
        let error = command.exec();
        ApiError::new(None, format!("cannot run {}: {error}", binary.display())).report();
    }

    #[cfg(not(unix))]
    {
        match command.status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(error) => {
                ApiError::new(None, format!("cannot run {}: {error}", binary.display())).report()
            }
        }
    }
}

fn unknown(name: &str) -> ! {
    let catalog = offline_catalog();

    if catalog.find(name).is_some() {
        ApiError {
            status: None,
            message: format!(
                "`{name}` is a module and it is not installed — run `mlab module install {name}`."
            ),
            kind: ErrorKind::Input,
        }
        .report();
    }

    // clap's own "did you mean" is switched off by the external sub-command that
    // routed us here, so a typo has to be caught by hand or every mistyped
    // built-in reads as a missing module.
    let mut candidates: Vec<String> = crate::builtin_names();
    candidates.extend(catalog.modules.iter().map(|m| m.name.clone()));
    let suggestion = closest(name, &candidates);

    let message = match suggestion {
        Some(hit) => format!("unrecognised command `{name}` — did you mean `{hit}`?"),
        None => format!(
            "unrecognised command `{name}` — see `mlab --help`, or `mlab module available`."
        ),
    };
    ApiError {
        status: None,
        message,
        kind: ErrorKind::Input,
    }
    .report();
}

fn closest(name: &str, candidates: &[String]) -> Option<String> {
    // One edit per three characters, so short names do not match everything.
    let budget = (name.len() / 3).max(1);
    candidates
        .iter()
        .map(|c| (distance(name, c), c))
        .filter(|(d, _)| *d <= budget)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c.clone())
}

/// Optimal string alignment, not plain Levenshtein: a transposition costs one
/// edit rather than two. `scna` for `scan` is the typo people actually make, and
/// plain Levenshtein scores it the same as two unrelated substitutions.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];

    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }

    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

/// The `Modules:` block appended to `mlab --help`, or `None` when nothing is
/// installed and there is nothing to list.
pub fn help_section() -> Option<String> {
    let registry = Registry::load();
    if registry.modules.is_empty() {
        return None;
    }

    let width = registry.modules.keys().map(String::len).max().unwrap_or(0);
    let mut out = String::from("Modules:\n");
    for (name, module) in &registry.modules {
        out.push_str(&format!(
            "  {name:<width$}  {}  {}\n",
            module.description, module.version
        ));
    }
    out.push_str("\nManage these with `mlab module`.");
    Some(out)
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// Deliberately not the shared client: `--timeout` is about the API, and these
/// transfers have nothing to do with it. Metadata gets a short leash so a stalled
/// network cannot make a command hang; a tarball gets a long one.
const METADATA_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

fn http(timeout: Duration) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("mlab-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

fn get_text(url: &str) -> Result<String, ApiError> {
    let response = http(METADATA_TIMEOUT)
        .get(url)
        .send()
        .map_err(ApiError::transport)?;
    let status = response.status();
    let body = response.text().unwrap_or_default();
    if status.is_success() {
        Ok(body)
    } else {
        Err(ApiError::from_response(status.as_u16(), &body))
    }
}

fn get_bytes(url: &str) -> Result<Vec<u8>, ApiError> {
    let response = http(DOWNLOAD_TIMEOUT)
        .get(url)
        .send()
        .map_err(ApiError::transport)?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(ApiError::from_response(status.as_u16(), &body));
    }
    response
        .bytes()
        .map(|b| b.to_vec())
        .map_err(ApiError::transport)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

pub fn available(json: bool) {
    let catalog = load_catalog(true);
    let registry = Registry::load();

    if json {
        let rows: Vec<serde_json::Value> = catalog
            .modules
            .iter()
            .map(|m| {
                serde_json::json!({
                    "name": m.name,
                    "binary": m.binary,
                    "repo": m.repo,
                    "description": m.description,
                    "installed": registry.modules.get(&m.name).map(|i| i.version.clone()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_default()
        );
        return;
    }

    if catalog.modules.is_empty() {
        println!("No modules in the catalogue.");
        return;
    }

    println!("{}", "Available modules".bold());
    println!();
    let width = catalog
        .modules
        .iter()
        .map(|m| m.name.len())
        .max()
        .unwrap_or(0);
    for module in &catalog.modules {
        let state = match registry.modules.get(&module.name) {
            Some(installed) => format!("installed {}", installed.version).green(),
            None => "not installed".dimmed(),
        };
        println!(
            "  {:<width$}  {}  {}",
            module.name.cyan(),
            module.description,
            state
        );
    }
    println!();
    println!(
        "{}",
        "Install one with `mlab module install <name>`.".dimmed()
    );
}

pub fn list(json: bool) {
    let registry = Registry::load();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&registry.modules).unwrap_or_default()
        );
        return;
    }

    if registry.modules.is_empty() {
        println!("No modules installed — see `mlab module available`.");
        return;
    }

    println!("{}", "Installed modules".bold());
    println!();
    let width = registry.modules.keys().map(String::len).max().unwrap_or(0);
    for (name, module) in &registry.modules {
        println!(
            "  {:<width$}  {}  {}",
            name.cyan(),
            module.version,
            format!("{} · {}", module.source, ago(module.installed_at)).dimmed()
        );
    }
}

pub fn which_module(name: &str) {
    match resolve(name) {
        Some(path) => println!("{}", path.display()),
        None => ApiError {
            status: None,
            message: format!("`{name}` is not installed."),
            kind: ErrorKind::NotFound,
        }
        .report(),
    }
}

pub fn install(name: &str, version: Option<&str>, from_source: bool, force: bool) {
    let catalog = load_catalog(true);
    let Some(entry) = catalog.find(name).cloned() else {
        let suggestion = closest(
            name,
            &catalog
                .modules
                .iter()
                .map(|m| m.name.clone())
                .collect::<Vec<_>>(),
        );
        ApiError {
            status: None,
            message: match suggestion {
                Some(hit) => format!("no module named `{name}` — did you mean `{hit}`?"),
                None => format!("no module named `{name}` — see `mlab module available`."),
            },
            kind: ErrorKind::NotFound,
        }
        .report();
    };

    // A module that shadowed a built-in would be unreachable anyway: clap owns
    // the name and the external sub-command never fires. Refusing here says so
    // instead of installing something that silently never runs.
    if crate::builtin_names().iter().any(|b| b == name) {
        ApiError {
            status: None,
            message: format!("`{name}` is a built-in mlab command — it cannot be a module."),
            kind: ErrorKind::Input,
        }
        .report();
    }

    let registry = Registry::load();
    if !force && registry.modules.contains_key(name) && version.is_none() {
        println!(
            "{} is already installed — `mlab module update {name}` or pass --force.",
            name.cyan()
        );
        return;
    }

    let installed = if from_source {
        install_from_source(&entry)
    } else {
        install_from_release(&entry, version)
    };

    let mut registry = Registry::load();
    registry.modules.insert(name.to_string(), installed.clone());
    registry.save();

    ui::success(&format!(
        "{} {} installed — run `mlab {name} --help`",
        name.cyan(),
        installed.version
    ));
}

fn install_from_release(entry: &CatalogEntry, version: Option<&str>) -> Installed {
    let target = host_target().unwrap_or_else(|| {
        ApiError {
            status: None,
            message: format!(
                "no release build for {}-{} — install with --from-source.",
                std::env::consts::ARCH,
                std::env::consts::OS
            ),
            kind: ErrorKind::Input,
        }
        .report()
    });

    if !entry.targets.is_empty() && !entry.targets.iter().any(|t| t == &target) {
        ApiError {
            status: None,
            message: format!(
                "{} publishes no {target} build — install with --from-source.",
                entry.name
            ),
            kind: ErrorKind::Input,
        }
        .report();
    }

    let version = match version {
        Some(v) => v.trim_start_matches('v').to_string(),
        None => latest_version(entry),
    };

    let asset = entry.asset_name(&version, &target);
    let base = format!(
        "{}/releases/download/v{version}",
        entry.repo.trim_end_matches('/')
    );

    // Every mlab release ships SHA256SUMS beside the archives. It comes from the
    // same release, so it proves integrity, not authenticity — it catches a
    // truncated or swapped download, not a compromised repository.
    let sums = ui::with_spinner(&format!("Resolving {} v{version}", entry.name), || {
        get_text(&format!("{base}/SHA256SUMS"))
    })
    .unwrap_or_else(|e| {
        // A 404 here is almost always a version that does not exist, and
        // "HTTP 404" on its own sends people looking in the wrong place.
        if e.status == Some(404) {
            ApiError {
                status: None,
                message: format!(
                    "{} has no v{version} release — see {}/releases.",
                    entry.name,
                    entry.repo.trim_end_matches('/')
                ),
                kind: ErrorKind::NotFound,
            }
            .report();
        }
        e.report()
    });

    let Some(expected) = checksum_for(&sums, &asset) else {
        ApiError {
            status: None,
            message: format!("{asset} is not listed in that release's SHA256SUMS."),
            kind: ErrorKind::NotFound,
        }
        .report();
    };

    let bytes = ui::with_spinner(&format!("Downloading {asset}"), || {
        get_bytes(&format!("{base}/{asset}"))
    })
    .unwrap_or_else(|e| e.report());

    let actual = sha256(&bytes);
    if actual != expected {
        ApiError {
            status: None,
            message: format!(
                "checksum mismatch for {asset} — expected {expected}, got {actual}. Nothing was installed."
            ),
            kind: ErrorKind::Other,
        }
        .report();
    }

    unpack(&bytes, &entry.binary);

    Installed {
        version,
        binary: entry.binary.clone(),
        repo: entry.repo.clone(),
        source: "release".to_string(),
        sha256: actual,
        description: entry.description.clone(),
        installed_at: now(),
    }
}

fn install_from_source(entry: &CatalogEntry) -> Installed {
    require_tool("git");
    require_tool("cargo");

    let checkout = sources_dir().join(&entry.name);
    let _ = fs::create_dir_all(sources_dir());

    if checkout.join(".git").is_dir() {
        run(
            Command::new("git")
                .arg("pull")
                .arg("--ff-only")
                .current_dir(&checkout),
            &format!("Updating {}", entry.name),
        );
    } else {
        run(
            Command::new("git")
                .arg("clone")
                .arg("--depth=1")
                .arg(&entry.repo)
                .arg(&checkout),
            &format!("Cloning {}", entry.repo),
        );
    }

    run(
        Command::new("cargo")
            .arg("build")
            .arg("--release")
            .current_dir(&checkout),
        &format!("Building {} (this takes a few minutes)", entry.name),
    );

    let built = checkout.join("target/release").join(&entry.binary);
    if !built.is_file() {
        ApiError {
            status: None,
            message: format!(
                "the build produced no {} at {}",
                entry.binary,
                built.display()
            ),
            kind: ErrorKind::Other,
        }
        .report();
    }

    let bytes = fs::read(&built).unwrap_or_else(|e| {
        ApiError::new(None, format!("cannot read {}: {e}", built.display())).report()
    });
    let installed_path = place(&entry.binary, &bytes);

    Installed {
        version: binary_version(&installed_path),
        binary: entry.binary.clone(),
        repo: entry.repo.clone(),
        source: "source".to_string(),
        sha256: sha256(&bytes),
        description: entry.description.clone(),
        installed_at: now(),
    }
}

pub fn update(name: Option<&str>) {
    let registry = Registry::load();
    if registry.modules.is_empty() {
        println!("No modules installed — see `mlab module available`.");
        return;
    }

    let names: Vec<String> = match name {
        Some(one) => {
            if !registry.modules.contains_key(one) {
                ApiError {
                    status: None,
                    message: format!("`{one}` is not installed."),
                    kind: ErrorKind::NotFound,
                }
                .report();
            }
            vec![one.to_string()]
        }
        None => registry.modules.keys().cloned().collect(),
    };

    let catalog = load_catalog(true);
    let mut changed = 0;

    for name in names {
        let current = registry.modules.get(&name).expect("checked above");
        let Some(entry) = catalog.find(&name) else {
            ui::warning(&format!("{name} is no longer in the catalogue — skipped"));
            continue;
        };

        // A source install is pinned to whatever the clone builds; re-resolving
        // it against the latest tag would silently swap it for a release binary.
        if current.source == "source" {
            let installed = install_from_source(entry);
            let mut registry = Registry::load();
            registry.modules.insert(name.clone(), installed.clone());
            registry.save();
            ui::success(&format!("{name} rebuilt at {}", installed.version));
            changed += 1;
            continue;
        }

        let latest = latest_version(entry);
        if latest == current.version {
            println!("{} is up to date ({})", name.cyan(), current.version);
            continue;
        }

        let installed = install_from_release(entry, Some(&latest));
        let mut registry = Registry::load();
        registry.modules.insert(name.clone(), installed);
        registry.save();
        ui::success(&format!("{name} {} → {latest}", current.version));
        changed += 1;
    }

    if changed == 0 {
        println!("Nothing to update.");
    }
}

pub fn remove(name: &str, purge: bool) {
    let mut registry = Registry::load();
    let Some(module) = registry.modules.remove(name) else {
        ApiError {
            status: None,
            message: format!("`{name}` is not installed."),
            kind: ErrorKind::NotFound,
        }
        .report();
    };

    let binary = bin_dir().join(&module.binary);
    if binary.exists() {
        if let Err(e) = fs::remove_file(&binary) {
            ApiError::new(None, format!("cannot remove {}: {e}", binary.display())).report();
        }
    }

    if purge {
        let checkout = sources_dir().join(name);
        if checkout.exists() {
            let _ = fs::remove_dir_all(&checkout);
        }
    }

    registry.save();
    ui::success(&format!("{} removed", name.cyan()));
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn latest_version(entry: &CatalogEntry) -> String {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        entry.slug()
    );
    let raw = ui::with_spinner(&format!("Resolving the latest {}", entry.name), || {
        get_text(&url)
    })
    .unwrap_or_else(|e| e.report());

    let tag = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("tag_name")?.as_str().map(str::to_string));

    match tag {
        Some(tag) => tag.trim_start_matches('v').to_string(),
        None => ApiError {
            status: None,
            message: format!("{} has no published release yet.", entry.name),
            kind: ErrorKind::NotFound,
        }
        .report(),
    }
}

/// Pull one file's hash out of a `sha256sum` listing.
fn checksum_for(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == asset).then(|| hash.to_lowercase())
    })
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Pull just the binary out of the archive. The destination path is ours, never
/// the archive's, so a crafted entry name cannot escape `~/.mlab/bin`.
fn unpack(bytes: &[u8], binary: &str) {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);

    let entries = archive
        .entries()
        .unwrap_or_else(|e| ApiError::new(None, format!("cannot read the archive: {e}")).report());

    for entry in entries {
        let Ok(mut entry) = entry else { continue };
        let is_binary = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|n| n == binary))
            .unwrap_or(false);
        if !is_binary {
            continue;
        }

        let mut buffer = Vec::new();
        if let Err(e) = std::io::copy(&mut entry, &mut buffer) {
            ApiError::new(None, format!("cannot extract {binary}: {e}")).report();
        }
        place(binary, &buffer);
        return;
    }

    ApiError {
        status: None,
        message: format!("the archive contains no {binary}."),
        kind: ErrorKind::Other,
    }
    .report();
}

/// Write the binary into `~/.mlab/bin` through a temporary file, so an
/// interrupted install leaves the previous version in place rather than a
/// half-written one.
fn place(binary: &str, bytes: &[u8]) -> PathBuf {
    let dir = bin_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        ApiError::new(None, format!("cannot create {}: {e}", dir.display())).report();
    }

    let final_path = dir.join(binary);
    let staging = dir.join(format!(".{binary}.new"));

    if let Err(e) = fs::write(&staging, bytes) {
        ApiError::new(None, format!("cannot write {}: {e}", staging.display())).report();
    }
    make_executable(&staging);

    if let Err(e) = fs::rename(&staging, &final_path) {
        let _ = fs::remove_file(&staging);
        ApiError::new(
            None,
            format!("cannot install {}: {e}", final_path.display()),
        )
        .report();
    }

    final_path
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

/// The release target triple for this host, or `None` when we do not publish
/// for it and only a source build can work.
fn host_target() -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        _ => return None,
    };
    let suffix = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        _ => return None,
    };
    Some(format!("{arch}-{suffix}"))
}

fn binary_version(path: &Path) -> String {
    Command::new(path)
        .arg("--version")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .last()
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn require_tool(tool: &str) {
    if which(tool).is_none() {
        ApiError {
            status: None,
            message: format!("`{tool}` is not on the PATH — needed for --from-source."),
            kind: ErrorKind::Input,
        }
        .report();
    }
}

fn run(command: &mut Command, message: &str) {
    let output = ui::with_spinner(message, || command.output());
    match output {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            ApiError::new(None, format!("{message} failed:\n{}", stderr.trim())).report();
        }
        Err(e) => ApiError::new(None, format!("{message} failed: {e}")).report(),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn ago(epoch: u64) -> String {
    if epoch == 0 {
        return "unknown".to_string();
    }
    let seconds = now().saturating_sub(epoch);
    match seconds {
        s if s < 3600 => "just now".to_string(),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_catalog_parses() {
        let catalog = parse_catalog(BUILTIN_CATALOG).expect("modules.json is valid");
        assert!(catalog.find("unifi").is_some());
    }

    #[test]
    fn module_names_cannot_be_paths() {
        assert!(is_module_name("unifi"));
        assert!(is_module_name("my-module2"));
        assert!(!is_module_name("../etc/passwd"));
        assert!(!is_module_name("/bin/sh"));
        assert!(!is_module_name("Unifi"));
        assert!(!is_module_name(""));
    }

    #[test]
    fn asset_names_follow_the_release_layout() {
        let catalog = parse_catalog(BUILTIN_CATALOG).unwrap();
        let unifi = catalog.find("unifi").unwrap();
        assert_eq!(
            unifi.asset_name("1.0.0", "aarch64-apple-darwin"),
            "mlab-unifi-1.0.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(unifi.slug(), "mlab-sh/mlab-unifi");
    }

    #[test]
    fn checksums_are_read_from_a_sha256sum_listing() {
        let sums = "abc123  mlab-unifi-1.0.0-x86_64-apple-darwin.tar.gz\n\
                    def456  mlab-unifi-1.0.0-aarch64-apple-darwin.tar.gz\n";
        assert_eq!(
            checksum_for(sums, "mlab-unifi-1.0.0-aarch64-apple-darwin.tar.gz"),
            Some("def456".to_string())
        );
        assert_eq!(checksum_for(sums, "nope.tar.gz"), None);
    }

    #[test]
    fn typos_suggest_the_nearest_command() {
        let candidates = vec!["scan".to_string(), "unifi".to_string()];
        assert_eq!(closest("scna", &candidates), Some("scan".to_string()));
        assert_eq!(closest("unfi", &candidates), Some("unifi".to_string()));
        assert_eq!(closest("wildly-different", &candidates), None);
    }
}
