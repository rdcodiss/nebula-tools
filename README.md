# Nebula Tools

[![Python 3.11](https://img.shields.io/badge/Python-3.11-9d00ff?style=for-the-badge)](https://docs.python.org/3.11/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f?style=for-the-badge)](LICENSE)

Nebula Tools is a Python 3.11 command-line toolkit by **@rdcodis**. It includes 47 tools for HTTP and DNS diagnostics, local file and inventory review, breach checks, and cryptography.

## 📦 Instalação

Use Python 3.11 and run this command from the project directory.

~~~sh
pip install -r requirements.txt
~~~

The requirements include Nebula0Crip file encryption and decryption with `cryptography` and local image EXIF review with `Pillow`.

## 🚀 Uso

~~~sh
python nebula.py
~~~

Type `I AGREE` when prompted. Enter `?` for the full tool guide, or `0` to exit.

## Highlights

| Options | What they do |
| --- | --- |
| 1–3, 6, 8–11, 32, 42 | Inspect DNS records, response headers, web pages, TLS certificates, cookies, and redirects. |
| 7 | Search public CVE records by keyword. Verify version applicability in the vendor advisory. |
| 24–25 | Check an email address on Have I Been Pwned in your browser, or check a password using the Pwned Passwords hash-prefix API. Set the optional `HIBP_API_KEY` environment variable to enable the in-terminal email lookup. |
| 26–31 | Preview temporary-file cleanup, import site lists, review local HTML, and summarize saved Web Vulnerability Scanner or TelaScan reports. |
| 33–34 | Encrypt or decrypt a single local file as a new copy using Nebula0Crip with AES-256-GCM and a passphrase-derived key. |
| 35–37, 41, 44–45 | Classify IP addresses, inspect public IP and reverse DNS, review saved Nmap XML, send a single ping, and generate documentation addresses. |
| 43, 46–47 | Review local image EXIF, search a read-only SQLite database, and create or verify salted scrypt password hashes. |

## Authorized use

Use the tools on systems you own or have explicit permission to assess. Some options contact public services, including [Have I Been Pwned](https://haveibeenpwned.com/), [NVD](https://www.nist.gov/itl/nvd), and [ipify](https://www.ipify.org/).

<img width="1397" height="797" alt="image" src="https://github.com/user-attachments/assets/9457b8ad-b4c9-4473-a18d-e38dc20ff9f5" />
