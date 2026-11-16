# Changelog

## 1.0.1 (2026-11-16)

### Fixed

- **LSA protection no longer leaves healthy machines INCOMPLETE.** Windows 11 can run LSASS
  protected with no `RunAsPPL` value set. In that case 1.0.0 recorded the check as INFO, the
  scorer never counted it, and an otherwise clean machine was capped at 74. Sentinel now reads the
  protection level LSASS is actually running with. If it can't, it falls back to the WinInit
  event from this boot and then to `RunAsPPL`. If none of those gives an answer it reports
  UNKNOWN, never a pass.
- **Safer report embedding.** `<`, `>` and `&` in the report JSON are now escaped before it goes
  into the dashboard's `<script>` element. 1.0.0 already stopped `</script>` from closing the
  element, but on PowerShell 7 a value containing `<!--<script>` could still break the page. The
  dashboard's own escaping now covers quotes too, and status values are checked against the known
  list before they're rendered.
- **SSH audits no longer dump progress records to stderr.** Storage and Defender cmdlets on the
  target ignored the local progress setting, so every SSH run printed a block of CLIXML.
- **SSH audits ignore stray output.** The report is tagged on the way out, so a login banner or
  profile output on the target can't be mistaken for it. Output is decoded as UTF-8 on Windows
  clients too.

### Added

- `tests/Test-HtmlReport.ps1`, which pushes hostile strings through the dashboard renderer and
  checks they stay inside the data. It fails against 1.0.0 on PowerShell 7.
- Scoring tests for LSA running state versus configuration, and a collector check that an elevated
  run reads the LSASS protection level.
- A `SentinelVersion` field in the JSON report. The console banner now shows the release version
  instead of "v3".

### Verified

- All test suites pass on Windows 11 (build 28020) under Windows PowerShell 5.1 and PowerShell 7.6.
- Remote audits were run against real Windows 11 hardware over SSH (from Linux, PowerShell 7.4)
  and over WinRM HTTPS with certificate validation (Windows PowerShell 5.1 and PowerShell 7.6).
  Results matched a local run.

## 1.0.0 (2026-11-16)

First release. Local and remote (WinRM / SSH) audits, report comparison, independent firewall
profile scoring, diagnostics, and an offline HTML dashboard.
