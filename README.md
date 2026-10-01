# outdated_os_scan.py

Subnet-wide deprecated/end-of-life OS discovery sweep, built the same way as
`ssh_vuln_scan.py` / `telnet_spray.py` / `quantum_readiness_spray.py` /
`sslspray.py`: masscan for fast discovery, then a worker pool running one
`nmap -O -sV` process per host, with the same live progress bar / logging
conventions. Single Python file — scan, parse, CSV, and `.xlsx` are all in
it. Ported from the original `outdatedOS.py` (still at the repo root,
untouched — a separate process handles retiring it).

## What it finds

Hosts whose nmap OS fingerprint matches a known deprecated/EOL operating
system at or above a confidence threshold, split into three **Risk
Category** buckets (unlike the 5-bucket sibling scripts, there is no "clean"
bucket here — this report only ever lists hosts that matched *some*
deprecated-OS rule, same scope as the original tool):

- 🔴 **Critical - Fully Unsupported (Legacy OS)** — no vendor patches
  available at all, for anything, including already-public CVEs (Windows
  95/98/2000/XP/Vista, Windows Server 2000/2003/2008, Linux 2.0–2.6.x,
  Solaris/SunOS, old FreeBSD/AIX, HP-UX, VMware ESXi 5.x).
- 🟠 **High - End of Life** — vendor support has ended or is ending
  imminently (Windows 7, Windows Server 2012, Linux 3.x kernels incl. RHEL
  7's 3.10, VMware ESXi 6.x, generic "Mac OS X 10.x").
- 🟡 **Watch - Recently / Soon End of Life** — still inside its support
  window at time of writing, but widely deployed and close enough to its
  own EOL date to flag now (currently just Windows 10, EOL 2025-10-14).

Per deprecated host: hostname (reverse DNS), OS family, the matched OS name
and its accuracy, every other `osmatch` nmap considered ("Alternate OS
Guesses"), a plain-English "Meaning" column, and notes with the rule's EOL
context.

Separately, the Overview sheet's **Scan Summary** tracks total live hosts
found in Phase 1, hosts that returned any OS-fingerprint data at all
("fingerprinted"), and hosts that returned none ("not fingerprinted" /
inconclusive) — these are scan-health metrics, not report-body categories.

## Why two phases

The configured scope (`SUBNETS` below) includes a `/8`. Pointing per-host
`nmap -O` probing at that much address space directly would dominate the
entire run. **Phase 1** uses masscan — a stateless SYN scanner — to find
which hosts across all configured subnets have one of a short list of
commonly-open ports open, in a fraction of the time. **Phase 2** then only
touches real hosts: a pool of worker threads each run one
`nmap -O -sV -Pn -n` process against one host.

## Scope

```python
SUBNETS: List[str] = [
    "1.0.0.0/16",
    "2.0.0.0/16",
    "3.0.0.0/16",
    "4.0.0.0/16",
    "5.0.0.0/16",
    # "6.0.0.0/16",
    "7.0.0.0/16",
    "8.0.0.0/12",
    "9.0.0.0/8",
]

MASSCAN_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3389,5900,8080"
```

Edit either in the script to change scope — same convention as the sibling
scripts.

## Requirements

- `masscan` on PATH (unless `--skip-masscan` with a valid
  `--masscan-output-file`) — needs root/Administrator to run
- `nmap` on PATH, always — unlike the original script, there is **no**
  `nmap -sn` discovery fallback for Phase 1, and no alternative engine for
  Phase 2 either. `-O` also requires raw-socket privileges, same as
  masscan — run with `sudo` / as Administrator.
- Python 3.8+
- `openpyxl` — only for the `.xlsx` step. If missing, the run degrades to
  CSV-only instead of failing. Imported lazily inside the workbook-building
  function, never at module level.

```bash
pip install openpyxl
```

## Usage

```bash
sudo python outdated_os_scan.py
```

| Flag | Default | Purpose |
|---|---|---|
| `--workers` | `10` | Concurrent `nmap -O -sV` processes in Phase 2 (lower than `ssh_vuln_scan.py`'s 16 — `-O -sV` is heavier per-host than NSE-script-only work) |
| `--rate` | `25000` | masscan packets/sec (Phase 1) **and** nmap's own `--max-rate` ceiling (Phase 2) — a single CLI flag covers both, since a per-host `--max-rate` ceiling this high never actually gets reached by one host's own probe traffic |
| `--host-timeout` | `60s` | nmap `--host-timeout` per host (longer than `ssh_vuln_scan.py`'s 30s — `-O`'s TCP/IP-stack fingerprint sends more probes and waits on more timing windows than an NSE script does) |
| `--retries` | `1` | Retries per host if nmap failed to launch or produced no usable XML at all (not retried for a deterministic "host answered, 0 osmatch" result — see Architecture notes) |
| `--min-accuracy` | `90` | Ignore `osmatch` guesses below this confidence (%) |
| `--output-dir` | script's own directory | Where the log/CSV/xlsx are written |
| `--masscan-path` / `--nmap-path` | `masscan` / `nmap` | Override the resolved binary path |
| `--interface` | *(none)* | Passed to masscan's `-e` |
| `--skip-masscan` + `--masscan-output-file` | — | Reuse a previous masscan run instead of re-scanning |
| `--keep-temp` | off | Keep each host's raw nmap XML under `<output-dir>/nmap_xml_<date>/` instead of deleting it |
| `--no-xlsx` | off | Stop after the CSV |
| `--csv-out` / `--xlsx-out` | derived from `--output-dir` | Override the output file paths |
| `--from-csv FILE` | — | Skip scanning entirely; rebuild the `.xlsx` from an existing CSV |

Resume from a previous masscan run:

```bash
python outdated_os_scan.py --skip-masscan --masscan-output-file .masscan_output_2026-10-01.txt
```

Rebuild just the `.xlsx` from an existing CSV without re-scanning:

```bash
python outdated_os_scan.py --from-csv outdated_os_scan_2026-10-01.csv
```

## Output

Everything is timestamped and written to `--output-dir`:

- `outdated_os_scan_<date>.log` — full run log (DEBUG-level to file, INFO-level to console)
- `outdated_os_scan_<date>.csv` — one row per **deprecated** host (same grain as the original script — not one row per scanned host)
- `outdated_os_scan_<date>.xlsx` — **Overview** + **Scan Results** sheets
- `.masscan_output_<date>.txt` — raw masscan hit list (hidden file, kept so `--skip-masscan` can reuse it)

### `outdated_os_scan_<date>.csv`

```
Scan Date,IP Address,Hostname,Subnet Range,OS Name,OS Family,Accuracy,Risk Category,Alternate OS Guesses,Notes,Meaning,Scan Status
```

### `outdated_os_scan_<date>.xlsx`

**Overview** — title/scan metadata, a "How to read this report" explainer,
the 3-category table (color + description), methodology notes explaining
the 2-phase design **and** specifically the osmatch-fix rationale, a Scan
Summary (live hosts discovered, hosts fingerprinted, hosts not
fingerprinted, total deprecated hosts + per-category counts/%), and a
subnet breakdown of the deprecated-host rows.

**Scan Results** — one row per deprecated host, frozen header, autofilter,
every row colored by its Risk Category (same red/orange/yellow palette as
the Overview table), `OS Name`/`Alternate OS Guesses`/`Notes`/`Meaning`
columns wrap-text enabled.

## What it checks and how it's classified

```
Windows 95              Windows client     CRITICAL   EOL 2001-12-31
Windows 98              Windows client     CRITICAL   EOL 2006-07-11
Windows Millennium      Windows client     CRITICAL   EOL 2006-07-11 (nmap also reports "Windows Me")
Windows 2000            Windows client     CRITICAL   EOL 2010-07-13
Windows XP              Windows client     CRITICAL   EOL 2014-04-08
Windows Vista           Windows client     CRITICAL   EOL 2017-04-11
Windows 7               Windows client     HIGH       EOL 2020-01-14
Windows 8               Windows client     HIGH       EOL 2016-01-12 (8.0) / 2023-01-10 (8.1) - substring also catches "Windows 8.1"
Windows 10              Windows client     WATCH      EOL 2025-10-14
Windows Server 2000     Windows Server     CRITICAL   EOL 2010-07-13
Windows Server 2003     Windows Server     CRITICAL   EOL 2015-07-14
Windows Server 2008     Windows Server     CRITICAL   EOL 2020-01-14 (substring also catches "2008 R2")
Windows Server 2012     Windows Server     HIGH       EOL 2023-10-10 (substring also catches "2012 R2")
Linux 2.0               Linux              CRITICAL   kernel EOL, long unsupported
Linux 2.2               Linux              CRITICAL   kernel EOL
Linux 2.4               Linux              CRITICAL   kernel EOL
Linux 2.6               Linux              CRITICAL   kernel EOL (all 2.6.x)
Linux 3.                Linux              HIGH       kernel EOL (3.0-3.19, incl. RHEL 7's 3.10 - trailing dot avoids "Linux 30"-style false positives)
Solaris                 Solaris / SunOS    CRITICAL   vendor EOL
SunOS                   Solaris / SunOS    CRITICAL   vendor EOL
FreeBSD 4 / 5 / 6 / 7    FreeBSD            CRITICAL   EOL
AIX 5 / 6                AIX                CRITICAL   EOL
HP-UX                   HP-UX              CRITICAL   EOL (generic match - specific version unknown from nmap fingerprint)
VMware ESXi 5           VMware ESXi        CRITICAL   EOL 2020-03-01
VMware ESXi 6           VMware ESXi        HIGH       EOL (6.0/6.5/6.7 all EOL)
Mac OS X                Mac OS X           HIGH       generic "Mac OS X 10.x" match - modern macOS reports as "macOS"
```

(Windows Server 2016+ is deliberately **not** flagged — its extended
support had not yet expired at the time this script, and the original it
was ported from, were written.)

`DEPRECATED_OS_RULES` is a list of `(keyword_substring, family,
risk_category, eol_note)` tuples evaluated in the order above — first
substring match (case-insensitive) wins. `classify_deprecated()` is the
single function that applies this table.

Classification of a host, per osmatch examined (`evaluate_osmatches()`):

1. Every `<osmatch>` child is walked in document order (nmap's own
   accuracy-descending sort).
2. Each one is recorded in "Alternate OS Guesses" (`name@accuracy%`),
   regardless of outcome.
3. The **first** one that is both `>= --min-accuracy` and matches a
   `DEPRECATED_OS_RULES` keyword becomes the host's reported OS/family/
   risk category — this is the osmatch-undercount fix described above.
4. A host with zero `<osmatch>` children, or where none qualify, is **not**
   in the report body, but counts toward "fingerprinted" (if `osmatch` data
   existed at all) or "not fingerprinted" (if it didn't) in the Scan
   Summary.

## Architecture notes

**Phase 1 (masscan)** is ported near-verbatim from the sibling scripts —
same live progress bar (percent/ETA parsed from masscan's own stderr), same
`-oL` list-output parsing, same dedup-by-key approach. The port spec is
`MASSCAN_PORTS`, copied verbatim from the original `outdatedOS.py` (a short
list of commonly-open ports that gives `nmap -O` something to anchor an
open/closed-port TCP/IP fingerprint on).

**Phase 2** is one `nmap -O -sV -Pn -n --max-rate <rate> --host-timeout
<timeout> -oX <tmpfile>` subprocess per host (`_run_nmap_single_host`),
mirroring `ssh_vuln_scan.py`'s `_run_nmap_single_host` / `scan_one_host` /
`_scan_one_host_inner` / `Phase2Stats` / `render_phase2_line` / `run_phase2`
pattern as closely as possible, including the temp-XML lifecycle (written
to a `tempfile.mkstemp()` path, parsed, then deleted — or moved under
`<output-dir>/nmap_xml_<date>/` if `--keep-temp` is set) and the "only
retry a failed/empty nmap invocation" rule: `parse_single_host_xml()`
returns `None` only when nmap failed to launch or produced no usable
`<host>` element at all (killed mid-write by `--host-timeout`, a disk
hiccup, unparseable XML) — that's the retry-worthy case. A host that
parsed fine but has **zero** `<osmatch>` children is a normal, deterministic
result (`fingerprinted=False`, `deprecated=False`) and is **not** retried.

**One bad host can't take down the batch** — same per-host exception
guarding (`scan_one_host`'s outer try/except) as the sibling scripts.

## Security notes

**CSV/Excel formula injection (CWE-1236) is neutralized.** `Hostname`,
`OS Name`, and `Alternate OS Guesses` are the fields sourced from external,
untrusted input (nmap's own fingerprint-database string, reverse DNS) —
`_neutralize_formula()` prefixes a single quote onto any such value
starting with `=`, `+`, `-`, `@`, tab, or CR before it reaches `csv.writer`
or an openpyxl cell, in both `write_csv_report()` and `build_workbook()`.
`Notes` and `Meaning` are built entirely from this script's own static
strings (`DEPRECATED_OS_RULES` EOL notes, `OS_RISK_MEANING`), so they are
not neutralized — there's nothing external in them to inject.

**A malformed nmap fingerprint string can't crash `.xlsx` generation.**
`_sanitize_text()` (ported verbatim from `telnet_spray.py`) strips
characters illegal in XML 1.0 — the same category of character that
crashes openpyxl with `IllegalCharacterError` — and caps every field at a
fixed length, applied at parse time in `parse_single_host_xml()` /
`evaluate_osmatches()` for the live-scan path, and again in
`read_rows_from_csv()` for a `--from-csv` rebuild, so a hand-edited or
externally-produced CSV can't reach openpyxl with an illegal character
either.

**A hand-edited or stale `--from-csv` file can't crash the rebuild.** The
`Risk Category` column is validated against the three canonical buckets on
load — an unrecognized value falls back to `High - End of Life` (logged as
a warning), and `Meaning` is always re-derived from that validated category
rather than read verbatim from the CSV, same consistency rule
`telnet_spray.py` applies to its own `Auth Category` / `Meaning` pair.

## Limitations

**Requires `masscan` on PATH for Phase 1 (no `nmap -sn` fallback), unlike
the original script, to match sibling-script convention.** None of
`ssh_vuln_scan.py` / `telnet_spray.py` / `sslspray.py` /
`quantum_readiness_spray.py` carry an `nmap -sn` discovery fallback either —
they hard-require masscan unless `--skip-masscan` is given with a valid
`--masscan-output-file`. Adding a fallback back in just for this tool would
make it the one inconsistent sibling.

**`openpyxl` is optional** — its absence degrades to CSV-only, imported
lazily so a missing install never breaks the scan itself.

**A masscan hit on a probed port only proves that port is open / the host
is alive — not that `nmap -O` will successfully fingerprint it.**
Firewalling of the *other* probe traffic nmap sends (closed-port resets,
ICMP, etc.) can still leave a host "not fingerprinted" even though Phase 1
found it alive. This is exactly what the Scan Summary's "fingerprinted" vs.
"not fingerprinted" counts are for.

**`nmap -O` is itself a heuristic best-effort match**, even for a result
reported above `--min-accuracy`. Treat every finding as a strong lead to
verify, not an absolute fact, same as any other passive OS-fingerprinting
technique.

**EOL dates/notes are approximate public knowledge, captured at the time
this script was written.** They are not guaranteed current — re-verify
against the vendor's own current lifecycle page before quoting a specific
date in a client-facing deliverable.

**Windows Server 2016+ is deliberately NOT flagged** — its extended
support had not yet expired at the time this script (and the original it
was ported from) was written. Re-evaluate `DEPRECATED_OS_RULES` as that
changes.

**Reverse DNS depends on corporate DNS infrastructure**; failures resolve
to `""` (blank) and do not stop the scan.

**Masscan and `nmap -O` both need elevated privileges** (raw sockets) — run
with `sudo` / as Administrator.

**`--from-csv` can't reconstruct the Scan Summary's live-host /
fingerprinted / not-fingerprinted counts.** The CSV schema only carries one
row per *deprecated* host (same grain as the original script) — the total
scanned/fingerprinted counts are a Phase-2-wide metric that doesn't survive
a round-trip through that per-deprecated-host CSV. A `--from-csv` rebuild's
Overview sheet shows those four rows as "N/A (not captured when rebuilding
from --from-csv)" rather than a fabricated number; the per-category
deprecated counts and subnet breakdown, which *are* derivable from the CSV,
are shown normally.

**Ctrl+C behavior**: first interrupt finishes in-flight work and writes
partial reports; second interrupt force-exits. Same as the sibling
scripts.

## Verification

This script was exercised locally (Python 3.13 + openpyxl available on this
machine, no masscan/nmap binary or root/Administrator privileges, so no
live network scan was attempted):

- `python -m py_compile outdated_os_scan.py` — passed clean.
- A synthetic-XML test harness (built in a scratch directory, deleted after
  the run) fed hand-built `nmap -O -sV` XML strings directly into
  `parse_single_host_xml()` / `evaluate_osmatches()`, covering: (1) the
  exact osmatch-undercount scenario from the module docstring —
  `osmatch[0]` = "Linux 5.4" (not deprecated, accuracy 93), `osmatch[1]` =
  "Linux 2.6.32" (CRITICAL, accuracy 91) — confirmed the host is correctly
  reported as "Linux 2.6.32" / CRITICAL / Linux family, with all three
  osmatch entries preserved in "Alternate OS Guesses"; (2) a host where the
  *highest*-accuracy osmatch is itself the deprecated one (Windows XP over
  Windows 7), confirming the fix doesn't over-correct into picking an
  arbitrary lower match; (3) both osmatch candidates below the accuracy
  threshold (fingerprinted, not deprecated); (4) a host with zero
  `<osmatch>` children (fingerprinted=False, no crash); (5) a host with no
  `<os>` element at all (same, no crash); (6) empty/malformed XML (returns
  `None`, the retry-worthy case, no crash). All 22 assertions across the 6
  cases passed.
- A `--from-csv` smoke test: a hand-written 3-row synthetic CSV (one host
  per risk category) was run through `python outdated_os_scan.py --from-csv
  <csv> --output-dir <scratch temp dir>`. Exit code 0, no exceptions. The
  resulting `.xlsx` was inspected directly with `openpyxl`: both `Overview`
  and `Scan Results` sheets present; `Scan Results` has the correct 12-column
  header, 3 data rows with the expected values, `freeze_panes == "A2"`, and
  `auto_filter.ref == "A1:L4"`; `Overview` has 33 rows including the
  category table, methodology notes (with the osmatch-fix paragraph), a
  Scan Summary showing the live/fingerprinted/not-fingerprinted rows as the
  expected "N/A (not captured when rebuilding from --from-csv)" (there is
  no live-scan stats sidecar for a CSV rebuild to draw from), correct
  per-category counts (1/1/1, 33.3% each), and a one-row subnet breakdown.
  The scratch CSV, scratch output directory, and test harness script were
  all deleted afterward — nothing left in the deliverable folder.
- **Not independently re-run**: Phase 1's masscan invocation code
  (`build_masscan_command` / `run_masscan_phase1` / `parse_masscan_list_output`)
  and Phase 2's actual `nmap -O -sV` subprocess invocation
  (`_run_nmap_single_host`) are ported near-verbatim from the already-proven
  sibling scripts (`ssh_vuln_scan.py` / `telnet_spray.py`) and were not
  independently re-run here — this machine has no masscan/nmap binary and
  no raw-socket privileges available. Same caveat the sibling scripts' own
  READMEs carry for their own untested pieces.
