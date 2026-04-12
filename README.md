<img width="1371" height="490" alt="banner" src="https://github.com/user-attachments/assets/60c6c9fe-2f40-4915-8df8-c70f39eda640" />


akha-sourcemap is a JavaScript Source Map downloader and information disclosure scanner.

Author: akha-security  
GitHub: https://github.com/akha-security

## Features

- Downloads `.js.map` files from a target URL or URL list
- Extracts source files and optionally recovers missing sources
- Scans extracted code with extensive disclosure/security patterns
- Generates terminal output, text report, and HTML report
- Includes passive endpoint verification mode

## Installation

```bash
pip install requests urllib3
```

## Usage

Single target:

```bash
python sourcemap_scanner.py -u https://example.com/app.js
```

URL list mode:

```bash
python sourcemap_scanner.py -f urls.txt
```

Save text report:

```bash
python sourcemap_scanner.py -u https://example.com/app.js -o report.txt
```

## Notes

- Use only on assets and systems you are authorized to test.
- This project is intended for security research and defensive auditing.
