<div align="center">

```
 ____  _____ _   _ _____ ___ _   _ _____ _
/ ___|| ____| \ | |_   _|_ _| \ | | ____| |
\___ \|  _| |  \| | | |  | ||  \| |  _| | |
 ___) | |___| |\  | | |  | || |\  | |___| |___
|____/|_____|_| \_| |_| |___|_| \_|_____|_____|
```

### Windows Security Posture Audit

**A read-only Windows hardening auditor that scores your box and hands you a cyberpunk report.**

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)
![Read only](https://img.shields.io/badge/mode-read--only-2fe38f)
![License](https://img.shields.io/badge/license-MIT-b98cff)

</div>

---

Sentinel walks your machine, checks the settings that actually decide whether it survives a bad
day — Secure Boot, TPM, BitLocker, VBS/HVCI, Credential Guard, Defender, the firewall, SMB, RDP,
UAC — and turns the result into a single **integrity score** and a stack of reports. It changes
**nothing**. No registry writes, no toggles, no "fixes". It looks, it grades, it leaves.

Every run drops a self-contained **[Sentinel HTML dashboard](docs/SENTINEL.md)** next to the CSVs —
one file, no dependencies, opens in any browser, online or off. That's the pretty one. This README
is about the engine and the terminal.

## What it looks like

```
  ==============================================================
  SYSTEM INTEGRITY  [#####################################-----]  89/100  FORTIFIED
  Solid baseline with a few gaps worth closing.

  PASS 29    WARN 4    FAIL 2    UNKNOWN 3    INFO 14
  ==============================================================
```

Findings are grouped by category and colour-coded on the console — green `PASS`, amber `WARN`,
red `FAIL`, violet `UNKNOWN`, grey `INFO` — with the *why* printed underneath anything that isn't
a pass. Full per-check detail lands in the exported files.

## Quick start

```powershell
# clone, then from the repo folder — right-click > Run as administrator for full results
.\WindowsSecurityAudit.ps1
```

If PowerShell blocks the script, unblock this one run without changing your machine policy:

```powershell
powershell -ExecutionPolicy Bypass -File .\WindowsSecurityAudit.ps1
```

> **Run elevated.** Sentinel works without admin rights, but BitLocker, TPM and some Defender
> queries return `UNKNOWN` unless it's running as Administrator.

## What it checks

| Area | Checks |
|------|--------|
| **System** | Edition / build / display version, model, CPU, RAM, BIOS/UEFI, pending reboot |
| **Boot & platform** | Firmware mode (UEFI/BIOS), Secure Boot, TPM presence / readiness / version / lockout |
| **Storage** | Physical disk health, Storage Spaces pools & virtual disks, resiliency, volume health, disk→volume mapping |
| **BitLocker** | OS + data volume encryption state, protection status, %, method, key protectors, recovery protector, auto-unlock |
| **Virtualisation security** | VBS, Memory Integrity / HVCI, Credential Guard, Secure Launch, kernel-mode HW stack protection |
| **Windows security** | LSA protection (RunAsPPL), Code Integrity policy |
| **Antivirus** | Registered products, Defender mode, real-time & behaviour monitoring, signatures, Tamper Protection |
| **Network** | Firewall profiles, SMBv1, SMBv2/3, SMB signing, insecure guest logons, RDP + NLA |
| **Privilege** | UAC, admin elevation policy, Secure Desktop prompting |

Sentinel deliberately separates **physical disks → pools → virtual disks → volumes → BitLocker**, so
pooled, spanned, JBOD or Storage Spaces layouts aren't mistaken for one-disk-per-drive-letter.

## Parameters

| Parameter | Effect |
|-----------|--------|
| `-OutputDirectory <path>` | Where reports are written. Default: `.\WindowsSecurityAudit\` |
| `-OpenReport` | Open the HTML dashboard in your browser when the scan finishes |
| `-NoHtml` | Skip the HTML dashboard (still writes JSON / TXT / CSV) |
| `-NoExport` | Console only — write no files at all |
| `-Quiet` | Suppress the console report |
| `-PassThru` | Return the structured report object to the pipeline |

```powershell
# scan, open the dashboard, and pull every failure into the pipeline
$audit = .\WindowsSecurityAudit.ps1 -OpenReport -PassThru
$audit.Checks | Where-Object Status -eq 'FAIL'
```

## Output files

Written to the output directory, stamped with hostname + timestamp:

- **`.html`** — the [Sentinel dashboard](docs/SENTINEL.md) (self-contained, shareable)
- **`.json`** — the full structured report (`SchemaVersion 3.0`) for pipelines and diffing
- **`.txt`** — a plain human-readable report
- **`_checks.csv`** and per-domain CSVs (physical disks, pools, virtual disks, volumes, BitLocker, antivirus)

## The integrity score

A single 0–100 number, weighted so warnings sting less than failures:

```
score = 100 × (PASS + 0.5 × WARN) / (PASS + WARN + FAIL)
```

`INFO` and `UNKNOWN` are excluded — they aren't judgements. The score maps to a band:

| Score | Band | Meaning |
|-------|------|---------|
| 90–100 | **HARDENED** | Strong. Remaining items are refinements. |
| 75–89 | **FORTIFIED** | Solid baseline, a few gaps to close. |
| 60–74 | **GUARDED** | Adequate, but protections are off or mis-firing. |
| 40–59 | **EXPOSED** | Core protections missing — start with the FAILs. |
| 0–39 | **COMPROMISED** | Critical protections absent. Treat as at-risk. |

Tune the weighting in `Get-PostureBand` and the score block near the summary.

## Requirements & safety

- Windows 10 / 11 (and recent Server), **Windows PowerShell 5.1** or **PowerShell 7+**
- **Read-only by design** — it performs no remediation and modifies nothing. Every write goes to
  the output directory you control.
- Reports describe your machine's security state. Treat them as sensitive; `.gitignore` already
  keeps generated reports out of the repo.

## License

MIT — see [LICENSE](LICENSE).
