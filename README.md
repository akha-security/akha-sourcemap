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

 ## Install
 ```bash
git clone https://github.com/akha-security/akha-sourcemap.git
cd akha-sourcemap
pip install requests urllib3
```


## Usage

```bash
# Single target
python sourcemap_scanner.py -u https://example.com/app.js

# URL list mode
python sourcemap_scanner.py -f urls.txt

# Save text report (Even if you use the -o parameter, it will generate an HTML report.)
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

## ⚠️ Disclaimer & Ethical Use

**AKHA-SOURCEMAP is developed for educational and authorized professional security testing purposes only.**

* Do NOT employ this tool against systems, networks, or applications that you do not hold explicit, documented permission to test.
* Use staging environments whenever possible. The developers assume zero liability and are not responsible for any misuse, damage, or legal consequences caused by the operation of this software. You act entirely at your own risk.



