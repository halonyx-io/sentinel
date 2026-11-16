# SENTINEL — the HTML readout

> The dashboard Sentinel writes at the end of every scan. One self-contained `.html` file with a
> score gauge, filtering and expandable findings. No server, no build step, no internet. Just
> double-click it.

Open [`examples/sentinel-report.example.html`](../examples/sentinel-report.example.html) in a
browser to see one. It's sample data for a made-up host.

![The Sentinel dashboard](dashboard.png)

## Why it exists

The console report is fine in a terminal and useless in an email, a ticket or a "can you check my
mum's laptop" message. The HTML file is the one you send. Score first, then the detail,
colour-coded so the problems stand out.

## What's in it

- **Score gauge**: the same 0–100 score as the console, with the band (`HARDENED` to `CRITICAL`)
  and a one-line verdict.
- **INCOMPLETE badge and coverage**: shown when Sentinel couldn't read everything it needs,
  usually because it wasn't run as admin.
- **Hard fails**: each failing critical control and the score cap it applies, so you can see why
  the number is what it is.
- **Not evaluated**: controls that returned nothing, listed as blind spots instead of left out.
- **Status tiles**: PASS / WARN / FAIL / UNKNOWN / INFO counts. Click one to filter the page.
- **Category panels**: every check, grouped. Click anything with detail to see what was found and
  what was expected.

It works with the keyboard, respects `prefers-reduced-motion`, and loads nothing from the
internet.

## How the data gets in

No external data file. At export time the script turns its report into JSON and drops it into
the page:

```powershell
$Json = $Report | ConvertTo-Json -Depth 12
$Json = $Json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026')
$html = $Template.Replace('@@REPORT_JSON@@', $Json)
```

The escaping matters. Collected values (machine names, product names, error messages) end up
inside a `<script>` element, and a value containing `</script>` or `<!--` could otherwise break out
of it. `tests/Test-HtmlReport.ps1` checks this with hostile strings. All dynamic text is
HTML-escaped again when the page renders it.

The score, band, coverage, verdict and hard fails are worked out once in PowerShell
(`Get-PostureAssessment`). The page just displays them and does no scoring of its own, so it can't
disagree with the console. [`examples/sentinel-report.template.html`](../examples/sentinel-report.template.html)
is the exact template, and `@@REPORT_JSON@@` is where the data goes.

## Design notes

Dark only, on purpose. It's meant to look like a terminal, not a document.

| Token | Value | Role |
|-------|-------|------|
| ground | `#08080f` | the void |
| panel | `#0e1020` | surfaces |
| cyan | `#3df0ff` | primary accent / system hue |
| magenta | `#ff2e88` | secondary accent (the synthwave pairing) |
| pass / warn / fail | `#2fe38f` / `#ffc24d` / `#ff4368` | semantic channel, kept separate from the accent |

Headings use **Chakra Petch** and data uses **JetBrains Mono** *if you have them installed*.
Nothing is downloaded, so otherwise it falls back to your system sans-serif and monospace fonts.
The scanlines and the gauge sweep are the only motion, and both turn off under reduced-motion.

## Customising it

Everything is in the `New-HtmlReport` here-string inside `WindowsSecurityAudit.ps1`:

- **Palette**: the CSS custom properties in `:root`.
- **Weights and caps**: the `$Map` table in `Get-PostureAssessment`. Bands are in `Get-PostureBand`.
  The page only renders what those produce, so there's one place to tune.
- **More panels**: `REPORT` also carries `Storage` (disks, pools, virtual disks, volumes,
  BitLocker) and `AntivirusProducts`. They're exported but not drawn yet.
- Any new field you render should go through `esc()`.

## Privacy

A report describes a real machine's security: Secure Boot state, disk serials, whether BitLocker
is on. Treat it like any other host inventory. `.gitignore` keeps real reports out of the repo.
Only the sample in `examples/` is meant to be shared.
