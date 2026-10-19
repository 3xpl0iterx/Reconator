# 1.0.0-rc.2 — 2026-10-19

- Detect apt, dnf/dnf5, yum, pacman, zypper or apk using distribution metadata
  and installed commands; map OS dependency names to the selected backend.
- Preview detected commands with `--plan`; override with `--package-manager`.
- Add `--system-only` for OS dependencies without provider builds/Python 3.12.
- Check optional tool package availability and skip installed tool commands;
  report unavailable packages without silently claiming a complete setup.
- Preserve fail-fast behavior and use the same detection in the interactive installer.
- Add offline backend routing, detection, preview and failure tests; document limits.

# 1.0.0-rc.1 — 2026-10-19

- Add MIT license selected by the owner.
- Replace partial unpinned installer with explicit setup plan, pinned Go versions
  and upstream provider commits, isolated Python 3.12 dependency sets, checked
  subprocess exits and final doctor gate.
- Preserve existing provider configuration/checkouts; serialize installations;
  initialize fresh Sudomy credential/notification examples with empty values.
- Fix fresh Sudomy initialization from its upstream `.api.dist` template.
- Verify the legacy Amass release binary by SHA-256 before atomic replacement.
- Match doctor interpreter selection to the OneForAll adapter.
- Add installer failure/configuration tests, source-only zip/checksum packaging,
  and integration tests against the extracted archive. CI runs the same checks.
- Document fresh setup, external licenses and service limitations.
- Stable promotion remains pending full fresh Kali installation validation.

# Changelog

## 0.5.0

- Removed the VPN prompt and connection integration.
- Grouped the menu, highlighted Full Recon, improved module progress/status and respected NO_COLOR/non-terminal output.
- Added per-tool Markdown/JSON/CSV reports and critical/high/medium/low/info/unknown JSON groups, including status reports for tools with no findings.
- Verified Full Recon schedules all 15 default modules through the same menu/CLI pipeline.

## 0.4.1

- Bounded interrupted report generation so reporting cannot hold shutdown open.
- Rechecked startup of all 15 installed commands and all provider adapter tests.
- Reconfirmed the historical Sonar endpoint returns HTTP 404.

## 0.4.0

- Unified menu and command-line execution; Full Recon runs the complete selected pipeline and automatically builds reports.
- Combined provider assets, Nmap, WHOIS, DNS, HTTP, httpx, Nuclei, Nikto and directory observations in severity-grouped reports. Enabled all Nuclei severities by default.
- Preserved informational/unknown classifications where evidence does not justify a vulnerability severity; no invented CVSS scores.
- Added manifests, explicit module statuses, timeouts, interrupted reports, child-process cleanup and guarded resume/archive behavior.
- Added scope/exclusion files, target batching, bounded concurrency, portable wordlists, scan comparison and Nmap profiles/port settings.
- Preserved custom ports 1–300 with service detection, terminal shortcut, VPN prompt, attribution, persistent menu and double Ctrl+C behavior.
- Added clean HTTPS-to-HTTP fallback with raw diagnostics retained in logs.
- Fixed theHarvester export filenames and Amass version-specific IP handling.
- Added offline doctor checks, fixture/integration/signal tests, ShellCheck, GitHub CI and ignores for generated data and credentials.
