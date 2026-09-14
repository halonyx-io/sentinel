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
  SYSTEM INTEGRITY  [#######################-------------------]  35/100  AT RISK
  Critical protections are off. This host is a soft target.

  HARD FAILS (each caps the score):
    x BitLocker / OS volume C:   -> score capped at 35
    x Boot Security / Secure Boot -> score capped at 55

  PASS 24    WARN 3    FAIL 2    UNKNOWN 0    INFO 5
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

> **Run elevated.** Sentinel works without admin rights (and still detects TPM presence/version),
> but BitLocker and some Defender/TPM detail return `UNKNOWN` unless it's running as Administrator —
> which marks the score **INCOMPLETE**. Run as Administrator for a full, trustworthy score.

## What it checks

| Area | Checks |
|------|--------|
| **System** | Edition / build / display version, model, CPU, RAM, BIOS/UEFI, pending reboot |
| **Boot & platform** | Firmware mode (UEFI/BIOS), Secure Boot, and the full TPM state matrix — absent / v1.2 / v2.0 / disabled / not-ready / ready / locked-out (presence & version detected even without admin) |
| **Storage** | Physical disk health, Storage Spaces pools & virtual disks, resiliency, volume health, disk→volume mapping |
| **Encryption** | OS + data volume encryption state, protection status, %, **encryption strength (XTS-AES-256 vs weaker)**, **key-protector quality (TPM+PIN > TPM-only > password/recovery)**, recovery protector, auto-unlock. Detection falls back through BitLocker cmdlets → the Device Encryption WMI provider (**works on Windows Home**) → third-party FDE detection (VeraCrypt, ESET, Sophos, Dell, McAfee, …) |
| **Antivirus** | A provider-agnostic *"is some real-time AV active and up to date?"* control decoded from Windows Security Center — so a passive Defender behind a healthy third-party AV passes, and an expired one fails |
| **Virtualisation security** | VBS, Memory Integrity / HVCI, Credential Guard, Secure Launch, kernel-mode HW stack protection |
| **Windows security** | LSA protection (RunAsPPL), Code Integrity policy |
| **Defender detail** | Defender running mode, real-time & behaviour monitoring, downloaded-file scanning, signature age, Tamper Protection |
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

The score is **not** an average of pass/fail counts (that lets 20 healthy disks bury a disabled
Secure Boot). It's a **risk-weighted, control-based model with hard-fail caps**, in the spirit of
Microsoft Secure Score and FAIR-CAM: each genuine security control carries a *weight* (its share of
the score) and, if critical, a *cap* (the highest score the machine may earn while that control is
failing). Informational checks — disk/volume health, system inventory, AV product lists — carry **no
weight** and never touch the score.

```
outcome:  PASS → 1.0   WARN → 0.5   FAIL → 0.0   UNKNOWN → excluded
base   = 100 × Σ(weight × outcome) / Σ(weight over known controls)
score  = min(base, lowest Cap among all FAILING critical controls)
```

So an **unencrypted OS drive alone caps the whole machine at 35**, and an **unencrypted fixed data
drive caps it at 65** — no number of healthy disks can rescue either. Caps stack by taking the
minimum. Emphasis is on **theft + malware resilience**: encryption, Secure Boot, TPM, antivirus and
the firewall dominate the weights.

**Blind spots are never passes.** Every required control that produces *no result at all* — a
missing cmdlet, a skipped section, a provider that threw — is reported as **NOT EVALUATED**, counted
against coverage, and if it's critical it applies its cap exactly as a failure would. A machine
Sentinel couldn't inspect can never score as a machine it inspected and liked.

| Score | Band | Meaning |
|-------|------|---------|
| 90–100 | **HARDENED** | Strong. Remaining items are refinements. |
| 75–89 | **FORTIFIED** | Solid baseline, a few gaps to close. |
| 60–74 | **GUARDED** | Adequate, but core protections need attention. |
| 40–59 | **EXPOSED** | Core protections missing — start with the FAILs. |
| 20–39 | **AT RISK** | Critical protections off. A soft target. |
| 0–19 | **CRITICAL** | Fundamental protections absent. |

**Coverage & INCOMPLETE.** Without elevation, Sentinel can't read BitLocker (and some Defender/TPM
detail). Rather than pretend, it reports a **coverage %**, marks the band **INCOMPLETE**, and refuses
the two green bands until you re-run as Administrator — a mostly-unreadable machine can never look
hardened. (TPM *presence* and *version* are still detected without admin via the security-device
enumeration, so a real TPM 2.0 is never mis-reported as missing.)

Tune the weights and caps in the `$Map` table inside `Get-PostureAssessment`, and the bands in
`Get-PostureBand`.

## Requirements & safety

- Windows 10 / 11 (and recent Server), **Windows PowerShell 5.1** or **PowerShell 7+**
- **Read-only by design** — it performs no remediation and modifies nothing. Every write goes to
  the output directory you control.
- Reports describe your machine's security state. Treat them as sensitive; `.gitignore` already
  keeps generated reports out of the repo.

## License

MIT — see [LICENSE](LICENSE).
