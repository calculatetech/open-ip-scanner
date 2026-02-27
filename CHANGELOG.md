# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - 2026-02-27

### Added
- Adapter `Auto Select` mode that chooses the best adapter for entered targets.
- Usage Guide dialog under `Help`.
- Target history autocomplete improvements and optional remember-last-target toggle in `Settings`.
- Service probes for `SMTP` (25), `SMTPS` (465), and `SMTP-STARTTLS` (587), disabled by default.
- Command preflight checks for non-web service/program launches with clearer error feedback.
- Numeric sorting keys for IP and MAC columns to ensure correct sort ordering.
- Per-adapter binding checks with explicit status warnings when binding fails.

### Changed
- Default adapter preference now prioritizes internet-routable physical adapters.
- `Auto` target fill now uses selected adapter ranges; `Auto Select` can fill all detected ranges.
- Default accuracy changed to `Balanced`.
- About dialog now shows application version.
- RDP default launcher restored to `xdg-open rdp://{host}:3389`.

### Fixed
- Target limit validation now marks input red and clears warning state when back in range.
- Large out-of-range CIDR/range edits no longer freeze the UI.
- Adapter changes no longer reset custom target input.
- Restoring remembered target on launch no longer gets overwritten during startup signal flow.
