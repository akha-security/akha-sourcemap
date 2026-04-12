<img width="1371" height="490" alt="banner" src="https://github.com/user-attachments/assets/60c6c9fe-2f40-4915-8df8-c70f39eda640" />


<div align="center">
  <h1>AKHA SourceMap Scanner</h1>
  <p><strong>Fast source map exposure scanner for JavaScript assets</strong></p>
  <p>
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#usage">Usage</a> •
    <a href="#disclaimer">Disclaimer</a>
  </p>
</div>

---

## Features

- Auto discovers and downloads `.js.map` files from JS URLs
- Extracts source files and tries to recover missing `sourcesContent`
- Scans code with a large security pattern set (keys, tokens, endpoints, PII)
- Optional passive endpoint verification with risk labels
- Generates terminal output, text report, and HTML report

## Quick Start

```bash
pip install requests urllib3
python sourcemap_scanner.py -u https://example.com/app.js
```

## Usage

```bash
# Single target
python sourcemap_scanner.py -u https://example.com/app.js

# URL list mode
python sourcemap_scanner.py -f urls.txt

# Save text report (HTML report is also generated)
python sourcemap_scanner.py -u https://example.com/app.js -o report.txt

# Passive verification mode
python sourcemap_scanner.py -u https://example.com/app.js --verify-passive
```

### Main Options

```text
-u, --url                 Single JS/JS.map URL to scan
-f, --file                File with target URLs
-o, --output              Text report file path
-t, --threads             Concurrent workers (default: 5)
--sources-dir             Source output directory (default: ./output)
--verify-passive          Enable passive endpoint verification
--verify-timeout          Verify timeout in seconds (default: 8)
--verify-max-targets      Max verification targets (default: 40)
```

## Scanner Screenshot
<img width="1504" height="911" alt="scanner" src="https://github.com/user-attachments/assets/60e48f8f-90f3-4abf-bd24-811863cb1bc2" />

## Report Screenshot
<img width="1515" height="760" alt="report" src="https://github.com/user-attachments/assets/adf0dc1e-570d-4130-964f-1b74422fd017" />



## Output

- Extracted source files in the selected output directory
- Text report if `-o` is provided
- HTML report generated automatically

## Disclaimer

Use this tool only on systems you are authorized to test.

<div align="center">
  <strong>Developed by akha-security</strong>
</div>

