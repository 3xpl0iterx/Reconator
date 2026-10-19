# Reconator 1.0.0-rc.3

Bash reconnaissance toolkit created by **3xpl0iter**. The existing `reconator` terminal shortcut still works. Requires Linux, Bash 5+, Python 3.8+ and the external tools used by the selected modules.

## Fresh installation

Automatic setup targets Linux x86_64, a regular (non-root) user, Bash 5+, and
Python 3.12 with pip/venv support for the optional Python providers. Reconator's
core uses system Python 3.8+. Install Python 3.12 separately if your distribution
uses a different version; pass its absolute path below. Go may download the
newer toolchain required by the pinned ProjectDiscovery tools. Builds need
additional disk space and network access.

```bash
# From the extracted/cloned Reconator source directory:
./reconator --help
python3 setup/install.py --plan
python3 setup/install.py --system --python /path/to/python3.12
./reconator doctor
# Optional terminal shortcut; keep the source directory in place:
mkdir -p "$HOME/.local/bin"
ln -s "$PWD/reconator" "$HOME/.local/bin/reconator"
```

The shortcut command deliberately refuses to overwrite an existing file. Add
`$HOME/.local/bin` to your PATH if needed. The interactive `--install` route uses
`RECONATOR_PROVIDER_PYTHON` when explicitly set, otherwise it verifies and selects
a working Python 3.12 from the running interpreter, PATH, existing provider venvs,
or installed pyenv versions (`PYENV_ROOT`, `pyenv root`, or `~/.pyenv`). Broken
pyenv shims are skipped during automatic detection; no global/local pyenv version
settings are changed. An explicit `--python`/environment override is validated and
fails clearly instead of silently falling back. OS dependencies use the detected
package manager; the plan prints the distribution, backend, package names and
commands. An explicit backend can be previewed even on another distribution:

```bash
python3 setup/install.py --plan --package-manager dnf
# OS dependencies only; no Python 3.12 requirement or provider builds:
python3 setup/install.py --system-only
# Full setup, with an optional explicit manager override:
python3 setup/install.py --system --package-manager dnf --python /path/to/python3.12
```

| Distribution family | Backend | Typical mapped packages |
|---|---|---|
| Debian / Ubuntu / Kali | apt (`apt-get`) | `golang-go`, `build-essential`, `dnsutils` |
| Fedora / RHEL derivatives | dnf (including `dnf5`) or yum | `golang`, `gcc`, `bind-utils` |
| Arch / Manjaro | pacman | `go`, `base-devel`, `bind` |
| openSUSE / SUSE | zypper | `go`, `gcc`, `bind-utils` |
| Alpine | apk | `go`, `build-base`, `bind-tools` |

Detection uses `/etc/os-release` and available manager commands, preferring the
host's distribution over a foreign package manager. Unknown/ambiguous systems
require an explicit `--package-manager` or manual OS setup. `--plan` makes no
changes or package queries. Installation uses sudo for OS packages. No additional
repositories are enabled, and pacman does not run a standalone database refresh
or automatic system upgrade; keep the host's repositories/system current yourself.

The OS package manager handles already installed base packages; available Nikto,
ffuf and theHarvester commands are skipped. Missing optional tool packages are
queried in the configured repositories and installed when available. If a package
is absent, setup reports the tool requiring manual installation. `--system-only`
returns failure when such gaps remain; full setup still requires doctor to pass.
Required-package installation or repository errors stop setup. Repository content
varies by distribution/release, and older enterprise systems may need packages
that are not in their enabled repositories.

These six backends are covered by offline routing tests, not fresh installations
of every distribution. Provider Python 3.12, native-library compatibility (including
musl-based systems), external API keys and services remain separate requirements.
Package-manager detection does not guarantee that every provider runs on every
Linux distribution. Install OS dependencies manually and omit `--system` when needed.

Amass 4.2.0 uses a SHA-256-verified official release binary to avoid compiling
legacy dependencies with newer Go. Other Go clients use pinned source versions.

Installation stops on failures; it never prints completion before doctor passes.
An existing provider checkout must match its pinned commit; local settings are
preserved. Interrupted `.install-*` directories/locks require inspection before
retrying. Requirements are pinned for compatibility with the legacy providers;
these are external programs with their own maintenance/security lifecycle.
Installing a client cannot make a defunct API work. Configure provider keys and
an available `CROBAT_API_BASE` separately. Nuclei also needs its templates; manage
those with Nuclei's own template commands. Directory discovery needs your own
wordlist. No wordlists, API keys, or scan results ship in the source release.

## License

Reconator source is MIT licensed; see LICENSE. External tools are downloaded
separately and retain their own licenses, including GPL-licensed providers.
They are not bundled or relicensed by the source archive.

## Interactive use

Run `reconator` to open the persistent menu immediately; VPN handling has been removed. Actions pause before returning to the menu; `00` exits. About displays the version.

**03 Full Recon now uses the same pipeline as the CLI:** ping, Nmap, HTTP inspection, WHOIS, DNS, all six providers, httpx, Nuclei, Nikto and optional directory discovery. It automatically generates reports and prints their locations. Enter the root domain and the separate active host when prompted. Directory discovery retains its authorization prompt.

**04 Public Subdomains** runs provider enumeration without WHOIS or the active host modules. **07 Analyze Results** regenerates reports; **08 Previous Scans** lists saved runs. **11** selects providers; **12** runs offline doctor. Menu labels and dispatch share one registry.

Ctrl+C once interrupts the current action and asks you to press Ctrl+C again to close. A normal answer cancels the pending exit. SIGINT exits use 130; SIGTERM uses 143. Partial scan evidence and interrupted status are retained. Interrupted report generation has a three-second deadline; if it cannot finish, rebuild reports from the preserved raw evidence with `reconator report SCAN_DIR`. Managed module processes are stopped and locks released. SIGKILL/power loss cannot run cleanup; verify no scan is running before manually removing a stale lock.

## Commands

```bash
reconator --help
reconator doctor
reconator full -d example.com --target www.example.com
reconator enum -d example.com --providers all
reconator passive -d example.com --providers subfinder,theharvester
reconator -m http -d https://example.com
reconator scan -t targets.txt --mode active --scope scope.txt --exclude exclusions.txt
reconator web -d example.com --severity all
reconator scan -d example.com --nmap-only --ports 1-300
reconator directory -d example.com --directory --wordlist /path/to/wordlist.txt
reconator enum -t targets.txt --providers subfinder --jobs 2
reconator history
reconator report /absolute/path/to/scan
reconator compare /path/to/older-scan /path/to/newer-scan
```

Bare mode aliases such as `reconator passive` prompt for input. No arguments open the full menu.

Targets are validated before any scan starts. Target files accept one domain/IP/HTTP URL per line, blank lines and `#` comments; duplicates are removed. Provider/DNS modes require a root domain. Active modes accept IPv4, IPv6, hostnames and HTTP URLs. Custom URL ports are rejected rather than silently discarded.

Scope/exclusion files contain domains or CIDRs. Scope rules apply to the supplied root and active host; excluded targets are omitted. Discovered subdomains do **not** automatically become active scan targets. Use tools within your assessment scope.

## Settings

| Setting | Behavior |
|---|---|
| `--providers LIST` | Six providers: subfinder, theharvester, oneforall, sudomy, amass, crobat; `all` selects all |
| Default providers | Full/subdomains: all; passive: subfinder, theharvester, crobat, sudomy |
| `--severity all` | Default: all Nuclei severities; accepts a comma-separated subset |
| `--timeout N` | Per-module deadline, default 300 seconds, including provider execution |
| `--http-timeout N` | HTTP request deadline, default 10 seconds |
| `--rate N`, `--threads N` | httpx/Nuclei/ffuf rate and concurrency, defaults 2/1; other providers use their own settings |
| `--jobs N` | Concurrent input targets, default 1, maximum 8; limits multiply across workers |
| `--ports SPEC` | Default preserves your ports 1–300 with service detection |
| `--profile quick` | Uses fast Nmap (`-F -T4`) |
| `--profile balanced` | Default Nmap settings |
| `--profile thorough` | Uses Nmap `-sVC` |
| `--fast`, `--aggressive` | Explicit Nmap alternatives |
| `--wordlist FILE` | Overrides `RECONATOR_WORDLIST` and the legacy Kali fallback |
| `--directory` | Enables directory testing in CLI Full/directory mode |

Missing/unreadable wordlists skip directory discovery. Reconator never downloads wordlists automatically. Installed providers may include their upstream bundled wordlists. Full scans can take time: each module prints its progress and has its own deadline.

HTTP inspection tries HTTPS then HTTP. It prints a clean fallback message and retains curl diagnostics in `http-errors.log`. HTTP 404/500 responses are valid responses, not connection failures. Nuclei/Nikto/ffuf use the successful HTTP scheme when available. All severity levels means all levels selected within Nuclei's normal template behavior; it does not override the scanner's default template exclusions.

## Providers and installation

Optional OneForAll and Sudomy sources are installed into `tools/`, with isolated Python 3.12 environments. `tools/bin` contains compatible Amass 4.2.0, ProjectDiscovery httpx 1.12.0 and Crobat; the system theHarvester is retained. Project-local tools take precedence inside Reconator without modifying shell startup files or system binaries. `setup/install.py --plan` lists the pinned source revisions and Go versions. New setups record these in `tools/setup-versions.json`; the original local setup also has `tools/installation.json`.

- **theHarvester:** configurable `HARVESTER_SOURCES` (default `crtsh`) and `HARVESTER_LIMIT`. Check installed help for available sources: older pasted sources such as Bing may be absent. Explicit export extensions prevent the installed version from truncating paths containing dots.
- **OneForAll:** `ONEFORALL_SCRIPT` / `ONEFORALL_PYTHON` override the installed script/environment. Main brute force, DNS resolution, HTTP probing and takeover checks are disabled; internal discovery may still issue DNS checks.
- **Sudomy:** `SUDOMY_SCRIPT` selects the installation. Its `sudomy.api` is created with empty key values and restrictive permissions; enter your own keys locally. Slack is disabled. The adapter uses `--no-probe` and loads the isolated environment and bundled utilities. Upstream cannot handle whitespace in output paths. A shared-directory lock prevents simultaneous Sudomy executions: use `--jobs 1` with Sudomy, or retry a busy phase using resume.
- **Amass:** `AMASS_BIN` overrides the binary. Supports legacy enum exports and v5's separate names export. `--amass-active` is explicit. `--amass-ip` uses a supported native flag/export where available; v4 address associations are extracted from available enumeration evidence without passing its unsupported `enum -ip` flag or forcing additional DNS scans. Some runs provide no address associations. System Amass v5's separate engine/libpostal requirements remain its own setup concern.
- **Crobat/Sonar:** the client is installed; Reconator calls the API directly. `CROBAT_API_BASE` changes the base URL. The historical Sonar endpoint returned 404; client installation cannot restore a discontinued/unavailable API. HTTP failures, invalid JSON and timeouts are reported, and other providers continue.

API-backed sources require your credentials and working services. Empty key files are not proof those sources are ready. Doctor is completely offline: it checks commands, Python imports, configuration-file presence, version, wordlist readability and results-directory permissions; it does not validate external keys/services. `--install` shows a pinned setup plan, asks before downloading, and returns failure if a step or final doctor check fails.

Official projects: [theHarvester](https://github.com/laramies/theHarvester), [OneForAll](https://github.com/shmilylty/OneForAll), [Sudomy](https://github.com/screetsec/Sudomy), [Amass](https://github.com/owasp-amass/amass), [Crobat/SonarSearch](https://github.com/Cgboal/SonarSearch).

## Reports and findings

Each scan has native evidence, per-module logs, `manifest.tsv`, phase state and reports:

```text
results/<root>/<scan>/
  domain.txt, target.txt, mode.txt, version.txt, scan-status.txt
  manifest.tsv                 module / status / exit code / evidence paths
  providers/<provider>/        separate raw exports and console logs
  logs/                        module diagnostics
  state/                       phase state and resume markers
  nmap.xml, nmap.txt            when Nmap ran
  http.txt, http-errors.log     when HTTP inspection ran
  subdomains.txt, subdomains_uniq.txt
  reports/
    report.md, report.json, findings.csv, subdomains.csv
    critical.json, high.json, medium.json, low.json, info.json, unknown.json
    tools/index.md
    tools/<tool>/report.md, report.json, findings.csv
    tools/<tool>/critical.json, high.json, medium.json, low.json, info.json, unknown.json
```

All tools feed the combined report:

- Provider discoveries are informational assets with deduplicated provider attribution. In-scope hosts, supported OSINT fields and Amass address associations are retained.
- Open ports, services, WHOIS, DNS, headers, responsive URLs and discovered paths are observations, not automatically vulnerabilities.
- Nuclei retains reported severity and supplied CVSS values. No scores are invented.
- Nikto findings without explicit severity remain **unknown**, requiring verification.
- Nmap scripts remain observations unless structured output explicitly reports a vulnerability; those unclassified vulnerabilities remain **unknown**.

Findings are deduplicated and sorted critical → high → medium → low → info → unknown. Reports show incomplete coverage, parser warnings and interrupted phases. Partial evidence never proves a scan completed. CSV exports protect formula-like finding text. Legacy reports can be rebuilt without overwriting original raw subdomain files.

Statuses distinguish success, no_data, failed, timeout, skipped, interrupted, pending and running. A blocked ping does not establish that a host is down; WHOIS with no recognized fields is no_data. Missing optional files/modules and failed remote services remain visible.

## Resume and comparison

`--resume` uses a stable scan directory; use it from the first run. `--resume-dir DIR` resumes a particular saved scan with matching root, active host and mode. Successful/no-data phases are reused; failures retry. Settings/code changes archive previous evidence under `archive/` and repeat phases. External binary upgrades, API changes or changed wordlist contents may require a fresh run.

`--output DIR` or `RECONATOR_RESULTS` changes the results root. A scan lock prevents simultaneous writes to the same resume directory. Comparison writes `reports/comparison.json` under the newer scan, showing added/removed assets and findings. Incomplete coverage can explain differences; absence is not proof an issue was fixed. Compare equivalent provider/settings coverage.

## Project layout and quality checks

`main.sh` loads absolute module paths and preserves the symlink launcher. Bash runtime checks explain unsupported shell use. Modules separate UI, validation, providers, reconnaissance, CLI/menu routing, runtime handling and reports.

```bash
for file in main.sh reconator lib/*.sh; do bash -n "$file"; done
shellcheck -x main.sh reconator lib/*.sh
python3 tests/test_parsers.py
python3 tests/test_cli.py
python3 tests/test_interrupt.py
```

Tests cover fixtures, all provider adapters, the actual menu-to-full-pipeline path, all severities, native curl against an owned local fixture API, HTTP fallback/404, scope, concurrency, resume/archive, timeout, Ctrl+C and SIGTERM. No external targets are scanned. `.github/workflows/offline.yml` runs these checks in CI. `.gitignore` excludes results, tools/environments, local credentials, logs and temporary files.

Live third-party behavior still needs verification in your own scope. No tests can guarantee remote API uptime or valid credentials. Original scripts and pre-upgrade source were backed up in the chat workspace; existing scan data remains in place.

## Per-tool reports in 0.5.0

Full Recon schedules all 15 modules by default: ping, Nmap, curl/HTTP, WHOIS, dig/DNS, Subfinder, theHarvester, OneForAll, Sudomy, Amass, Crobat, httpx, Nuclei, Nikto and ffuf/directory discovery. Explicit provider selections remain supported. Directory discovery can still be declined; unreadable wordlists and unavailable services are shown as skipped/failed rather than hidden.

`reports/tools/index.md` links to independent reports for every scheduled tool, including failed, pending and skipped tools. Each folder contains Markdown, JSON, CSV and six severity JSON files. Curl, dig and ffuf folders correspond to HTTP, DNS and directory modules. Shared discoveries appear in each contributing provider's report with their original attribution. An empty critical file is not proof the target is safe; check the phase status and coverage.

The menu opens directly without a VPN prompt, uses grouped sections, identifies Full Recon clearly and shows module progress/status. Non-interactive output and `NO_COLOR` disable terminal color escapes. Existing system VPN connections are not changed.

## Release verification

Run `bash scripts/check.sh` with Bash, Python 3 and ShellCheck installed. This is
also the GitHub Actions check. It runs parser fixtures, all mocked CLI/provider
integrations, actual terminal signal tests, installer contracts, all six package-manager backends and an extracted
source-archive integration test. `python3 scripts/package.py /path/to/output`
builds a source-only zip and SHA-256 checksum without installed tools, API keys
or scan results. Verify the checksum before sharing.

This is the 1.0 release candidate. The stable label is pending a complete fresh
Kali installation including OS packages and pinned Go builds. Actual GitHub
provider fetches and the Amass binary download/checksum have passed. Fresh isolated Python
provider checks and offline integration tests do not substitute for that check.
Live API-backed providers also depend on the user's keys and working upstream
services. Crobat's historical endpoint remains unavailable; configure a compatible
endpoint or omit that provider explicitly. No stable release has been published.
