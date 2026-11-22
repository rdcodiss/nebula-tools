# Nebula Tools

Nebula Tools is a Python 3.11 command-line toolkit by **@rdcodis**. It includes 47 tools for HTTP and DNS diagnostics, local file and inventory review, breach checks, and cryptography.

## Install and run

Run these commands from the directory containing `nebula.py`. On Windows, use `py -3.11` in place of `python3.11` if you use the Python launcher.

~~~sh
python3.11 -m pip install requests beautifulsoup4 rich dnspython python-whois
python3.11 nebula.py
~~~

Type `I AGREE` when prompted. Enter `?` for the full tool guide, or `0` to exit.

Install the optional packages for the features you want to use.

~~~sh
python3.11 -m pip install cryptography Pillow
~~~

`cryptography` enables Nebula0Crip file encryption and decryption. `Pillow` enables local image EXIF review.

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

## Usage

Use the tools on systems you own or have explicit permission to assess. Some options contact public services, including [Have I Been Pwned](https://haveibeenpwned.com/), [NVD](https://www.nist.gov/itl/nvd), and [ipify](https://www.ipify.org/).
