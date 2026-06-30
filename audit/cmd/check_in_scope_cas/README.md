# check_in_scope_cas

A tool that cross-checks the "In-Scope CAs" listed in a WebTrust audit report PDF against the canonical CA certificate list published in the [sectigo/ca_certificate_lists](https://github.com/sectigo/ca_certificate_lists) GitHub repository.

## What It Does

1. Extracts text from an audit report PDF (the "Attachment B/C – In-Scope CAs" section) using `pdftotext`.
2. Parses the extracted table into records containing Subject DN, SHA-256 thumbprint, Valid From, and Valid To dates.
3. Downloads the latest [`list_for_audit.csv`](https://github.com/sectigo/ca_certificate_lists/blob/main/audit/list_for_audit.csv) from GitHub.
4. Filters the CSV to Sectigo-owned, non-revoked certificates that are in-scope for the specified audit type.
5. Compares the two sets and reports anomalies:
   - Certificate hashes in the CSV but missing from the PDF.
   - Certificates hashes in the PDF but not in-scope in the CSV.
   - Mismatches in Subject DN, Valid From, or Valid To dates.

## Prerequisites

- **Go** 1.25 or later
- **pdftotext** (part of the [poppler-utils](https://poppler.freedesktop.org/) package)

Install `pdftotext` on Debian/Ubuntu:

```sh
sudo apt install poppler-utils
```

On macOS:

```sh
brew install poppler
```

## Building

```sh
go build -o check_in_scope_cas .
```

## Usage

```
check_in_scope_cas <audit-report-pdf-file> <scope>
```

### Arguments

| Argument | Description |
|---|---|
| `<audit-report-pdf-file>` | Path to the WebTrust audit report PDF containing an "In-Scope CAs" attachment. |
| `<scope>` | The audit scope to check. One of: `CA`, `BRSSL`, `EVSSL`, `CS`, `SMIME`, `NETSEC`, `MC`. |

The scope maps to the corresponding `WT<scope>?` column in the CSV (e.g., `BRSSL` → `WTBRSSL?`).

### Example

```sh
./check_in_scope_cas "Sectigo_WTBR_2025.pdf" BRSSL
```

## Output

- **`<basename>.txt`** — The full `pdftotext` output is saved to the current directory.
- **`list_for_audit.csv`** — The downloaded CSV is saved to the current directory.
- **Anomalies** are printed to stdout. If no anomalies are found, it prints `No anomalies found.`
- **Progress and warnings** are printed to stderr.
