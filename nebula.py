# Python 3.11 dependencies
# python -m pip install requests beautifulsoup4 rich dnspython python-whois
# Optional Nebula0Crip encryption dependency
# python -m pip install cryptography
# Optional Image EXIF dependency
# python -m pip install Pillow
"""Nebula Arsenal by @rdcodis.

Use only on systems you own or have explicit permission to assess.
You are responsible for staying within the authorized scope. Type I AGREE
at startup to open the menu.
"""

import ast
import base64
import binascii
import csv
import getpass
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import stat
import string
import subprocess
import sys
import tempfile
import time
import tokenize
import warnings
import webbrowser
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qsl, quote, urldefrag, urljoin, urlsplit

import dns.exception
import dns.resolver
import requests
import whois
from bs4 import BeautifulSoup
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from whois.exceptions import WhoisError

PURPLE = "#9d00ff"
CREDIT = "@rdcodis"
HTTP_TIMEOUT = (5, 8)
LOOKUP_TIMEOUT = 8
MAX_HTML_BYTES = 2_000_000
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_LIMIT = 5
HIBP_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_WEB_URL = "https://haveibeenpwned.com/"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range/"
HIBP_AGENT = "Nebula-Arsenal"
PUBLIC_IP_URL = "https://api64.ipify.org"
CRIP_MAGIC = b"NEBULA0CRIP\x01"
CRIP_SALT_SIZE = 16
CRIP_NONCE_SIZE = 12
CRIP_HEADER_SIZE = len(CRIP_MAGIC) + CRIP_SALT_SIZE + CRIP_NONCE_SIZE
CRIP_TAG_SIZE = 16
CRIP_MAX_BYTES = 32 * 1024 * 1024
CONSOLE = Console()

LOGO = r"""
    _   __     __          __
   / | / /__  / /_  __  __/ /___ _
  /  |/ / _ \/ __ \/ / / / / __  /
 / /|  /  __/ /_/ / /_/ / / /_/ /
/_/ |_/\___/_.___/\__,_/_/\__,_/
""".strip("\n")

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Browsers may use HTTP on subsequent visits.",
    "Content-Security-Policy": "The browser has one fewer layer of protection against injected scripts.",
    "X-Frame-Options": "Clickjacking protection may be absent unless CSP defines frame-ancestors.",
    "X-Content-Type-Options": "Browsers may interpret a resource as a different MIME type.",
}


def show_logo() -> None:
    if CONSOLE.is_terminal:
        CONSOLE.clear()
    logo = LOGO if CONSOLE.width >= 40 else "Nebula"
    CONSOLE.print(
        Panel.fit(
            Align.center(Text(logo, style=f"bold {PURPLE}", no_wrap=True)),
            title="Nebula Arsenal",
            subtitle=f"by {CREDIT}",
            border_style=PURPLE,
            padding=(0, 2),
        )
    )


def ask(label: str, **kwargs) -> str:
    return Prompt.ask(label, console=CONSOLE, **kwargs).strip()


def ask_file(label: str, **kwargs) -> Path:
    value = ask(label, **kwargs)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if not value:
        raise ValueError("Enter a file path.")
    return Path(value).expanduser()


def confirm_usage() -> bool:
    CONSOLE.print(
        Panel(
            "Use only on systems you own or have explicit permission to assess. "
            "You are responsible for staying within the authorized scope.",
            title="Usage notice",
            border_style=PURPLE,
        )
    )
    try:
        accepted = ask("Type I AGREE to continue") == "I AGREE"
    except (EOFError, KeyboardInterrupt):
        CONSOLE.print()
        accepted = False
    if not accepted:
        CONSOLE.print("Agreement declined. Exiting Nebula Arsenal.", style="yellow")
    return accepted


def literal(value: object) -> Text:
    # Render remote data and user input without interpreting terminal markup.
    return Text("".join(char if char.isprintable() else " " for char in str(value)))


def make_table(title: str, *columns: str) -> Table:
    table = Table(title=title, title_style=f"bold {PURPLE}", header_style=f"bold {PURPLE}")
    for name in columns:
        table.add_column(name, overflow="fold")
    return table


def normalize_domain(value: str) -> str:
    domain = value.removesuffix(".").encode("idna").decode("ascii").lower()
    labels = domain.split(".")
    if (
        len(domain) > 253
        or len(labels) < 2
        or labels[-1].isdigit()
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    ):
        raise ValueError("Enter a valid domain, such as example.com.")
    return domain


def normalize_http_url(value: str) -> str:
    value = value.strip()
    if not value or value.startswith("//") or "\\" in value or any(
        char.isspace() or not char.isprintable() for char in value
    ):
        raise ValueError("Enter an HTTP(S) URL or hostname, without spaces.")
    url = value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else f"https://{value}"
    parts = urlsplit(url)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise ValueError("Enter an HTTP(S) URL or hostname without credentials.")
    if parts.netloc.startswith("[") and not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", parts.netloc):
        raise ValueError("Enter a valid bracketed IP address and optional port.")
    if parts.port == 0 or parts.netloc.endswith(":"):
        raise ValueError("Use a port from 1 through 65535.")
    return urldefrag(url).url


def ask_domain() -> str:
    url = normalize_http_url(ask("Domain or HTTP(S) URL"))
    return normalize_domain(urlsplit(url).hostname)


def query_dns(
    resolver: dns.resolver.Resolver, domain: str, record_type: str, *, txt_version: str | None = None
) -> list[str]:
    try:
        try:
            records = resolver.resolve(domain, record_type, lifetime=LOOKUP_TIMEOUT, search=False)
        except dns.resolver.LifetimeTimeout:
            records = resolver.resolve(domain, record_type, tcp=True, lifetime=4, search=False)
        if txt_version is not None:
            values = [b"".join(record.strings).decode("utf-8", errors="replace") for record in records]
            version = re.compile(rf"^{re.escape(txt_version)}(?:[\s;]|$)", re.IGNORECASE)
            return [value for value in values if version.match(value)] or ["No matching policy"]
        return [record.to_text() for record in records]
    except dns.resolver.NXDOMAIN:
        return ["DNS name does not exist"]
    except dns.resolver.NoAnswer:
        return ["No records of this type"]
    except dns.resolver.LifetimeTimeout:
        return ["System resolver timed out over UDP and TCP"]
    except (dns.exception.DNSException, OSError) as error:
        return [f"Lookup failed ({type(error).__name__})"]


def nebula_recon() -> None:
    domain = ask_domain()
    record_types = ("A", "MX", "NS", "TXT")
    table = make_table("DNS and WHOIS", "Source", "Field", "Result")

    with ThreadPoolExecutor(max_workers=5) as executor:
        registration = executor.submit(
            whois.whois, domain, timeout=LOOKUP_TIMEOUT, quiet=True, ignore_socket_errors=False
        )
        try:
            resolver = dns.resolver.Resolver()
            dns_queries = {
                record_type: executor.submit(query_dns, resolver, domain, record_type)
                for record_type in record_types
            }
            for record_type, query in dns_queries.items():
                for value in query.result():
                    table.add_row("DNS", record_type, literal(value))
        except (dns.exception.DNSException, OSError) as error:
            table.add_row("DNS", "Resolver", literal(f"Unavailable ({type(error).__name__})"))

        try:
            record = registration.result()
        except (WhoisError, ValueError, OSError) as error:
            table.add_row("WHOIS", "Lookup", literal(f"Unavailable ({type(error).__name__})"))
        else:
            for key, label in (
                ("registrar", "Registrar"),
                ("creation_date", "Registration date"),
                ("emails", "Public email addresses"),
            ):
                value = record.get(key)
                if isinstance(value, (list, tuple)):
                    value = ", ".join(str(item) for item in value if item)
                table.add_row("WHOIS", label, literal(value or "Not provided"))

    CONSOLE.print(table)


def ask_url() -> str:
    return normalize_http_url(ask("HTTP(S) URL or hostname"))


def nebula_headers() -> None:
    url = ask_url()
    with requests.get(url, timeout=HTTP_TIMEOUT, stream=True) as response:
        CONSOLE.print(literal(f"HTTP {response.status_code}  {response.url}"))
        table = make_table("Security headers", "Header", "Status", "Notes")
        for header, risk in SECURITY_HEADERS.items():
            present = header in response.headers
            if header == "Strict-Transport-Security" and urlsplit(response.url).scheme != "https":
                observation = "HSTS applies only to HTTPS responses."
            elif not present:
                observation = risk
            elif not response.headers[header].strip():
                observation = "The header has an empty value."
            else:
                observation = "Value received"
            status = Text("Present", style="green") if present else Text("Missing", style="red")
            table.add_row(header, status, observation)
        CONSOLE.print(table)
        CONSOLE.print("Review header values to confirm the policy fits the application.")


def read_html(response: requests.Response) -> bytes:
    content_type = response.headers.get("Content-Type", "").partition(";")[0].strip().lower()
    if content_type and content_type not in {"text/html", "application/xhtml+xml"}:
        raise ValueError("The response content type is not HTML.")
    deadline = time.monotonic() + 10
    html = bytearray()
    for chunk in response.iter_content(chunk_size=32_768):
        if time.monotonic() > deadline:
            raise ValueError("Reading the page exceeded the time limit.")
        html.extend(chunk)
        if len(html) > MAX_HTML_BYTES:
            raise ValueError("The page exceeds the 2 MB size limit.")
    return bytes(html)


def parse_html_response(response: requests.Response) -> BeautifulSoup:
    content = Message()
    content["Content-Type"] = response.headers.get("Content-Type", "")
    return BeautifulSoup(read_html(response), "html.parser", from_encoding=content.get_content_charset())


def resolve_http_url(base_url: str, reference: str) -> str | None:
    try:
        url = urljoin(base_url, reference)
        parts = urlsplit(url)
        if parts.scheme in {"http", "https"} and parts.hostname:
            return url
    except ValueError:
        pass
    return None


def nebula_crawler() -> None:
    url = ask_url()
    with requests.get(url, timeout=HTTP_TIMEOUT, stream=True) as response:
        response.raise_for_status()
        page_url = response.url
        soup = parse_html_response(response)

    base_tag = soup.find("base", href=True)
    base_url = page_url
    if base_tag is not None:
        base_url = resolve_http_url(page_url, base_tag["href"]) or page_url

    anchors = soup.find_all("a", href=True)
    forms = soup.find_all("form")
    CONSOLE.print(f"Links ({len(anchors)}) · Forms ({len(forms)})")

    if anchors:
        table = make_table("Page links", "Destination")
        for anchor in anchors:
            href = anchor["href"].strip()
            table.add_row(literal(resolve_http_url(base_url, href) or href))
        CONSOLE.print(table)

    if forms:
        table = make_table("Page forms", "Method", "Destination")
        for form in forms:
            method = (form.get("method") or "").strip().upper() or "GET"
            action = (form.get("action") or "").strip()
            target = resolve_http_url(base_url, action) if action else page_url
            table.add_row(literal(method), literal(target or action))
        CONSOLE.print(table)


def parse_port_filter(value: str) -> set[int] | None:
    if not value:
        return None
    ports = set()
    for part in value.split(","):
        bounds = re.fullmatch(r"([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?", part.strip())
        if not bounds:
            raise ValueError("Enter ports and ranges such as 80,443,8000-8080.")
        start = int(bounds[1])
        end = int(bounds[2] or bounds[1])
        if not 1 <= start <= end <= 65535:
            raise ValueError("Enter ports from 1 through 65535 and put range bounds in ascending order.")
        ports.update(range(start, end + 1))
    return ports


def local_tcp_listeners() -> set[tuple[int, str]]:
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        command = [str(system_root / "System32" / "netstat.exe"), "-ano"]
        backend = "windows"
    elif sys.platform.startswith("linux") and (ss := shutil.which("ss")):
        command = [ss, "-H", "-ltn"]
        backend = "ss"
    else:
        netstat = shutil.which("netstat")
        if netstat is None:
            raise OSError("The local listener inventory requires ss or netstat.")
        command = [netstat, "-an"]
        backend = "netstat"

    output = subprocess.run(
        command, check=True, capture_output=True, text=True, errors="replace", timeout=8
    ).stdout
    listeners = set()
    for line in output.splitlines():
        fields = line.split()
        if backend == "ss" and len(fields) >= 5 and fields[0] == "LISTEN":
            endpoint = fields[3]
        elif backend == "windows" and len(fields) >= 5 and fields[0].upper() == "TCP":
            if fields[2] not in {"0.0.0.0:0", "[::]:0"}:
                continue
            endpoint = fields[1]
        elif (
            backend == "netstat"
            and len(fields) >= 6
            and fields[0].lower() in {"tcp", "tcp4", "tcp6", "tcp46"}
            and fields[5] == "LISTEN"
        ):
            endpoint = fields[3]
        else:
            continue

        separator = "." if backend == "netstat" and sys.platform == "darwin" else ":"
        _, _, port = endpoint.rpartition(separator)
        if port.isascii() and port.isdecimal() and 1 <= int(port) <= 65535:
            listeners.add((int(port), endpoint))
    return listeners


def nebula_port_scan() -> None:
    ports = parse_port_filter(ask("Local port filter, or press Enter for all", default="", show_default=False))
    table = make_table("Local TCP listeners", "Port", "Local address", "Typical service")
    for port, endpoint in sorted(local_tcp_listeners()):
        if ports is not None and port not in ports:
            continue
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "Unknown"
        table.add_row(str(port), literal(endpoint), literal(service))
    if table.row_count:
        CONSOLE.print(table)
    else:
        CONSOLE.print("No local TCP listeners match the filter.")


def read_routes(path: Path) -> set[str]:
    routes = set()
    with path.open(encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            route = line.strip()
            if not route or route.startswith("#"):
                continue
            if not route.startswith("/") or route.startswith("//") or any(
                char.isspace() or char in "?#" or not char.isprintable() for char in route
            ):
                raise ValueError(f"Expected one URL path per line. Invalid entry on line {line_number}.")
            routes.add(route)
    return routes


def nebula_fuzzer() -> None:
    CONSOLE.print("Provide two UTF-8 text files with one URL path per line, such as /docs.")
    expected = read_routes(ask_file("Approved public path list"))
    observed = read_routes(ask_file("Published public path inventory"))
    table = make_table("Published path review", "Path", "Result")
    for route in sorted(observed - expected):
        table.add_row(literal(route), Text("Published without approval", style="red"))
    for route in sorted(expected - observed):
        table.add_row(literal(route), Text("Approved and missing from inventory", style="yellow"))
    if table.row_count:
        CONSOLE.print(table)
    else:
        CONSOLE.print("The two inventories contain the same paths.")
    CONSOLE.print(f"Approved paths ({len(expected)}) · Published paths ({len(observed)})")


def nebula_subdomain() -> None:
    domain = ask_domain()
    names = ask("Full hostnames from your inventory, separated by commas")
    hosts = dict.fromkeys(normalize_domain(name.strip()) for name in names.split(","))
    if any(not host.endswith(f".{domain}") for host in hosts):
        raise ValueError("Every hostname must be a subdomain of the supplied domain.")

    resolver = dns.resolver.Resolver()
    table = make_table("Subdomain DNS verification", "Subdomain", "Type", "Result")
    for host in hosts:
        for record_type in ("A", "AAAA"):
            for value in query_dns(resolver, host, record_type):
                table.add_row(literal(host), record_type, literal(value))
    CONSOLE.print(table)


def nebula_cve() -> None:
    term = " ".join(ask("Technology or version, for example apache 2.4.49").split())
    if not term:
        raise ValueError("Enter a technology to search the NVD.")

    params = {"keywordSearch": term, "resultsPerPage": CVE_LIMIT}
    with requests.get(NVD_CVE_URL, params=params, timeout=HTTP_TIMEOUT) as response:
        response.raise_for_status()
        try:
            data = response.json()
        except ValueError as error:
            raise ValueError("The NVD response was not JSON.") from error

    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("The NVD returned an unexpected response format.")

    records = data["vulnerabilities"]
    if not records:
        CONSOLE.print("The NVD returned no CVEs for that search.")
        return

    table = make_table("CVE Lookup · National Vulnerability Database", "CVE", "Published", "Description")
    for entry in records[:CVE_LIMIT]:
        cve = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
            raise ValueError("The NVD returned a record without a CVE identifier.")

        entries = cve.get("descriptions")
        if not isinstance(entries, list):
            entries = []
        descriptions = {
            item["lang"]: item["value"]
            for item in entries
            if isinstance(item, dict) and isinstance(item.get("lang"), str) and isinstance(item.get("value"), str)
        }
        description = descriptions.get("en") or "English description unavailable."
        published = str(cve.get("published") or "").partition("T")[0]
        table.add_row(literal(cve["id"]), literal(published or "Not provided"), literal(description))

    CONSOLE.print(table)
    CONSOLE.print("This is a keyword search. Confirm version applicability in the vendor advisory.")


def nebula_dns_policy() -> None:
    domain = ask_domain()
    resolver = dns.resolver.Resolver()
    table = make_table("Published DNS policy records", "Check", "Name", "Record")
    for label, name, record_type, version in (
        ("SPF", domain, "TXT", "v=spf1"),
        ("DMARC", f"_dmarc.{domain}", "TXT", "v=DMARC1"),
        ("CAA", domain, "CAA", None),
        ("DNSSEC delegation", domain, "DS", None),
    ):
        for value in query_dns(resolver, name, record_type, txt_version=version):
            table.add_row(label, literal(name), literal(value))
    CONSOLE.print(table)


def nebula_tls() -> None:
    target = urlsplit(ask_url())
    if target.scheme != "https":
        raise ValueError("Enter an HTTPS URL to inspect its TLS certificate.")
    hostname = target.hostname
    port = target.port if target.port is not None else 443
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=LOOKUP_TIMEOUT) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as tls:
            cert = tls.getpeercert()
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            version = tls.version() or "Unknown"
            cipher = tls.cipher()

    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    issuer = ", ".join(f"{key}={value}" for group in cert["issuer"] for key, value in group)
    alternative_names = ", ".join(value for _, value in cert.get("subjectAltName", ()))
    table = make_table("Verified TLS certificate", "Field", "Value")
    for label, value in (
        ("Endpoint", target.netloc),
        ("Protocol", version),
        ("Cipher", cipher[0] if cipher else "Unknown"),
        ("Issuer", issuer),
        ("Expires (UTC)", expires.isoformat(timespec="seconds")),
        ("Subject alternative names", alternative_names or "None"),
        ("SHA-256 fingerprint", fingerprint),
    ):
        table.add_row(label, literal(value))
    CONSOLE.print(table)


def nebula_cookies() -> None:
    url = ask_url()
    with requests.get(url, timeout=HTTP_TIMEOUT, stream=True, allow_redirects=False) as response:
        cookies = response.raw.headers.getlist("Set-Cookie")
        CONSOLE.print(literal(f"HTTP {response.status_code}  {response.url}"))

    table = make_table("Response cookie attributes", "Name", "Secure", "HttpOnly", "SameSite")
    for header in cookies:
        cookie, *attributes = header.split(";")
        name, separator, _ = cookie.partition("=")
        if not separator or not name.strip():
            continue
        flags = {}
        for attribute in attributes:
            key, _, value = attribute.partition("=")
            flags[key.strip().casefold()] = value.strip()
        secure = Text("Present", style="green") if "secure" in flags else Text("Missing", style="yellow")
        http_only = Text("Present", style="green") if "httponly" in flags else Text("Missing", style="yellow")
        same_site = flags.get("samesite", "").casefold()
        if "samesite" not in flags:
            same_site_display = "Not set"
        elif same_site in {"strict", "lax", "none"}:
            same_site_display = same_site.title()
        else:
            same_site_display = "Invalid"
        table.add_row(literal(name.strip()), secure, http_only, same_site_display)

    if table.row_count:
        CONSOLE.print(table)
    else:
        CONSOLE.print("No cookies found in the response.")


def nebula_redirects() -> None:
    url = ask_url()
    with requests.Session() as session:
        session.max_redirects = 8
        with session.get(url, timeout=HTTP_TIMEOUT, stream=True) as response:
            chain = [*response.history, response]

    table = make_table("HTTP redirect chain", "Hop", "Status", "URL", "Observation")
    previous_scheme = urlsplit(url).scheme
    for hop, response in enumerate(chain):
        scheme = urlsplit(response.url).scheme
        observation = Text("HTTPS to HTTP", style="yellow") if previous_scheme == "https" and scheme == "http" else ""
        table.add_row(str(hop), str(response.status_code), literal(response.url), observation)
        previous_scheme = scheme
    CONSOLE.print(table)


def nebula_file_integrity() -> None:
    path = ask_file("File path")
    algorithm = ask("Hash algorithm", choices=["sha256", "sha512"], default="sha256")
    expected = ask("Expected hex digest, or press Enter to compute only", default="", show_default=False).lower()
    if expected and not re.fullmatch(rf"[0-9a-f]{{{hashlib.new(algorithm).digest_size * 2}}}", expected):
        raise ValueError(f"Enter a full hexadecimal {algorithm.upper()} digest.")

    with path.open("rb") as source:
        digest = hashlib.file_digest(source, algorithm).hexdigest()
    table = make_table("File integrity", "Algorithm", "Digest")
    table.add_row(algorithm.upper(), literal(digest))
    CONSOLE.print(table)
    if expected:
        if hmac.compare_digest(digest, expected):
            CONSOLE.print("Digest matches.", style="green")
        else:
            CONSOLE.print("Digest mismatch.", style="red")


def nebula_config_diff() -> None:
    reference_path = ask_file("Reference JSON file")
    current_path = ask_file("Current JSON file")
    reference = load_json(reference_path)
    current = load_json(current_path)
    if not isinstance(reference, dict) or not isinstance(current, dict):
        raise ValueError("Both files must contain a top-level JSON object.")

    table = make_table("Top-level configuration drift", "Key", "Result")
    for key in sorted(reference.keys() - current.keys()):
        table.add_row(literal(key), Text("Missing from current config", style="yellow"))
    for key in sorted(current.keys() - reference.keys()):
        table.add_row(literal(key), Text("Added to current config", style="yellow"))
    for key in sorted(reference.keys() & current.keys()):
        if json.dumps(reference[key], sort_keys=True) != json.dumps(current[key], sort_keys=True):
            table.add_row(literal(key), "Value changed")
    if table.row_count:
        CONSOLE.print(table)
    else:
        CONSOLE.print("No differences found.")


def nebula_python_review() -> None:
    path = ask_file("Python source file")
    with tokenize.open(path) as source:
        tree = ast.parse(source.read(), filename=str(path))

    subprocess_calls = {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
    findings = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        function = call.func
        if isinstance(function, ast.Name) and function.id in {"eval", "exec"}:
            findings.append((call.lineno, function.id, "Review whether untrusted text can reach this call."))
        if not isinstance(function, ast.Attribute) or not isinstance(function.value, ast.Name):
            continue
        qualified_name = f"{function.value.id}.{function.attr}"
        if qualified_name in {"pickle.load", "pickle.loads", "yaml.unsafe_load"}:
            findings.append((call.lineno, qualified_name, "Review the trust boundary for serialized data."))
        if qualified_name in subprocess_calls and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call.keywords
        ):
            findings.append((call.lineno, qualified_name, "Review shell invocation and argument handling."))

    if not findings:
        CONSOLE.print("No matching calls found by the source checks.")
        return

    table = make_table("Python source review", "Line", "Call", "Review")
    for line, call, note in sorted(findings):
        table.add_row(str(line), call, note)
    CONSOLE.print(table)


def nebula_http_log_summary() -> None:
    path = ask_file("HTTP log CSV with method and status columns")
    statuses = Counter()
    methods = Counter()
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source, strict=True)
        fields = reader.fieldnames or []
        if len(fields) != len(set(fields)):
            raise ValueError("The CSV header contains duplicate column names.")
        if not {"method", "status"}.issubset(fields):
            raise ValueError("The CSV header must include method and status.")
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"Column count does not match the CSV header near line {reader.line_num}.")
            method = (row.get("method") or "").strip()
            status = (row.get("status") or "").strip()
            if not re.fullmatch(r"[!#$%&'*+.^_|\x60~0-9A-Za-z-]+", method) or not re.fullmatch(r"[1-5][0-9]{2}", status):
                raise ValueError(f"Invalid HTTP method or status near CSV line {reader.line_num}.")
            statuses[status] += 1
            methods[method] += 1

    if not statuses:
        CONSOLE.print("The CSV contains no HTTP request records.")
        return

    table = make_table("HTTP log summary", "Group", "Value", "Count")
    for status, count in sorted(statuses.items()):
        table.add_row("Status", status, str(count))
    for method, count in methods.most_common():
        table.add_row("Method", method, str(count))
    CONSOLE.print(table)


def nebula_url_inspector() -> None:
    url = urlsplit(ask_url())
    parameters = dict.fromkeys(name for name, _ in parse_qsl(url.query, keep_blank_values=True))
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    table = make_table("URL components", "Component", "Value")
    for label, value in (
        ("Scheme", url.scheme),
        ("Hostname", url.hostname),
        ("Port", port),
        ("Path", url.path or "/"),
        ("Query names", ", ".join(parameters) or "None"),
    ):
        table.add_row(label, literal(value))
    CONSOLE.print(table)


def nebula_cidr() -> None:
    interface = ipaddress.ip_interface(ask("IPv4 or IPv6 address and prefix, such as 192.0.2.5/24"))
    network = interface.network
    table = make_table("CIDR calculation", "Field", "Value")
    for label, value in (
        ("Input IP", interface.ip),
        ("Network", network),
        ("First address", network.network_address),
        ("Last address", network.broadcast_address),
        ("Total addresses", network.num_addresses),
    ):
        table.add_row(label, literal(value))
    CONSOLE.print(table)


def load_json(path: Path) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"Unsupported JSON constant: {value}")

    with path.open(encoding="utf-8-sig") as source:
        try:
            return json.load(source, object_pairs_hook=unique_object, parse_constant=reject_constant)
        except RecursionError as error:
            raise ValueError("The JSON document is nested too deeply.") from error


def nebula_json_validator() -> None:
    value = load_json(ask_file("JSON file"))
    root_types = {
        dict: "Object",
        list: "Array",
        str: "String",
        int: "Number",
        float: "Number",
        bool: "Boolean",
        type(None): "Null",
    }
    table = make_table("Valid JSON", "Field", "Value")
    table.add_row("Root type", root_types[type(value)])
    if isinstance(value, (list, dict)):
        table.add_row("Top-level items", str(len(value)))
    CONSOLE.print(table)


def nebula_csv_inspector() -> None:
    path = ask_file("CSV file")
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.reader(source, strict=True)
        headers = next(reader, [])
        if not headers or any(not name.strip() for name in headers) or len(headers) != len(set(headers)):
            raise ValueError("The CSV needs a header row with unique, non-empty column names.")
        rows = 0
        irregular = 0
        first_irregular = None
        for row in reader:
            if not row:
                continue
            rows += 1
            if len(row) != len(headers):
                irregular += 1
                if first_irregular is None:
                    first_irregular = reader.line_num

    table = make_table("CSV structure", "Field", "Value")
    table.add_row("Columns", literal(", ".join(headers)))
    table.add_row("Data rows", str(rows))
    table.add_row("Rows with a different column count", str(irregular))
    if first_irregular is not None:
        table.add_row("First irregular row ends on line", str(first_irregular))
    CONSOLE.print(table)


def nebula_file_metadata() -> None:
    path = ask_file("File path")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Choose a regular file.")
    media_type, _ = mimetypes.guess_type(path.name)
    modified = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc)
    table = make_table("File metadata", "Field", "Value")
    table.add_row("Name", literal(path.name))
    table.add_row("Size (bytes)", str(info.st_size))
    table.add_row("Modified (UTC)", modified.isoformat(timespec="seconds"))
    table.add_row("Media type inferred from filename", media_type or "Unknown")
    CONSOLE.print(table)


def nebula_http_status() -> None:
    code = ask("HTTP status code, such as 404")
    if not re.fullmatch(r"[1-5][0-9]{2}", code):
        raise ValueError("Enter a three-digit HTTP status code.")
    try:
        status = HTTPStatus(int(code))
    except ValueError:
        CONSOLE.print("This code has no entry in the Python 3.11 HTTP status reference.")
        return
    table = make_table("HTTP status reference", "Code", "Name", "Meaning")
    table.add_row(code, status.phrase, status.description or "No description available.")
    CONSOLE.print(table)


def nebula_timestamp() -> None:
    value = ask("Unix seconds or ISO timestamp with offset, such as 2026-01-01T12:00:00Z")
    if re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value):
        try:
            instant = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OSError, OverflowError) as error:
            raise ValueError("Timestamp is outside the supported range.") from error
    else:
        instant = datetime.fromisoformat(value)
        if instant.tzinfo is None:
            raise ValueError("Include a UTC offset or Z on an ISO timestamp.")
        try:
            instant = instant.astimezone(timezone.utc)
        except OverflowError as error:
            raise ValueError("Timestamp is outside the supported range.") from error

    table = make_table("Timestamp conversion", "Format", "Value")
    table.add_row("ISO 8601 (UTC)", instant.isoformat())
    table.add_row("Unix seconds", str(instant.timestamp()))
    CONSOLE.print(table)


def nebula_password() -> None:
    length_input = ask("Password length (16–128)", default="24")
    if not re.fullmatch(r"[0-9]{2,3}", length_input) or not 16 <= int(length_input) <= 128:
        raise ValueError("Choose a password length from 16 through 128.")
    length = int(length_input)
    groups = (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation)
    alphabet = "".join(groups)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(char in group for char in password) for group in groups):
            break
    CONSOLE.print(Text(password, no_wrap=True, overflow="ignore"))


def nebula_email_breaches() -> None:
    api_key = os.environ.get("HIBP_API_KEY", "").strip()
    mode = ask("Lookup method", choices=["browser", "api"], default="browser") if api_key else "browser"
    if mode == "browser":
        Thread(target=open_hibp_page, daemon=True).start()
        CONSOLE.print(f"Enter your email on the official Have I Been Pwned page to see the results. {HIBP_WEB_URL}")
        return
    if not re.fullmatch(r"[a-fA-F0-9]{32}", api_key):
        raise ValueError("HIBP_API_KEY must be a 32-character hexadecimal key.")
    CONSOLE.print("The address you enter is sent to Have I Been Pwned.")
    email = ask("Your email address or an address you are authorized to check")
    if not re.fullmatch(r"[^\s@,<>;]+@[^\s@,<>;]+\.[^\s@,<>;]+", email):
        raise ValueError("Enter one email address.")

    try:
        with requests.get(
            HIBP_ACCOUNT_URL + quote(email, safe=""),
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": api_key, "User-Agent": HIBP_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        ) as response:
            if response.status_code == 404:
                CONSOLE.print("HIBP found no publicly disclosable matches for that address.")
                return
            if response.status_code in {401, 403}:
                raise ValueError("HIBP rejected the key or the subscription does not allow this lookup.")
            if response.status_code == 429:
                raise ValueError("HIBP rate limited the request. Try again later.")
            if response.status_code != 200:
                raise ValueError(f"HIBP returned HTTP {response.status_code}.")
            records = response.json()
    except requests.exceptions.JSONDecodeError:
        raise ValueError("HIBP returned invalid JSON.") from None
    except requests.RequestException:
        raise ValueError("Could not reach the HIBP email lookup service.") from None

    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise ValueError("HIBP returned an unexpected response format.")
    if not records:
        CONSOLE.print("HIBP found no publicly disclosable matches for that address.")
        return

    table = make_table("Have I Been Pwned · Reported breaches", "Breach", "Date", "Domain", "Data types")
    for record in records:
        title = record.get("Title") or record.get("Name") or "Unknown"
        data_classes = record.get("DataClasses")
        if not isinstance(data_classes, list):
            data_classes = []
        categories = ", ".join(value for value in data_classes if isinstance(value, str))
        table.add_row(
            literal(title),
            literal(record.get("BreachDate") or "Unknown"),
            literal(record.get("Domain") or "Unknown"),
            literal(categories or "Unknown"),
        )
    CONSOLE.print(table)
    CONSOLE.print(HIBP_WEB_URL)


def open_hibp_page() -> None:
    try:
        webbrowser.open_new_tab(HIBP_WEB_URL)
    except (OSError, webbrowser.Error):
        # The main thread always shows the direct link.
        return


def ask_secret(label: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(f"{label} (hidden): ")
        except getpass.GetPassWarning:
            raise ValueError("This terminal cannot safely hide secret input.") from None


def nebula_password_exposure() -> None:
    password = ask_secret("Password to check")
    if not password:
        raise ValueError("Enter a password to check.")
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    del password

    try:
        with requests.get(
            HIBP_PASSWORD_URL + digest[:5],
            headers={"Add-Padding": "true", "User-Agent": HIBP_AGENT},
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise ValueError(f"Pwned Passwords returned HTTP {response.status_code}.")
            lines = response.text.splitlines()
    except requests.RequestException:
        raise ValueError("Could not reach the Pwned Passwords service.") from None

    matched = 0
    valid_rows = 0
    for line in lines:
        suffix, _, count = line.partition(":")
        if not re.fullmatch(r"[0-9A-F]{35}", suffix) or not re.fullmatch(r"[0-9]+", count):
            continue
        valid_rows += 1
        if hmac.compare_digest(suffix, digest[5:]):
            matched = int(count)
    if not valid_rows:
        raise ValueError("Pwned Passwords returned an unexpected response format.")
    if matched:
        CONSOLE.print(f"This password appeared {matched:,} times in the dataset. Replace it wherever it was used.", style="red")
    else:
        CONSOLE.print("This password was not found in the Pwned Passwords dataset.")


def is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def nebula_temp_cleanup() -> None:
    days = ask("Minimum age in days", default="7")
    if not re.fullmatch(r"[0-9]{1,4}", days) or int(days) < 1:
        raise ValueError("Enter a positive age in days.")
    cutoff = time.time() - int(days) * 86400
    root = Path(tempfile.gettempdir()).resolve(strict=True)
    if root == Path(root.anchor) or root == Path.home().resolve() or root == Path.cwd().resolve():
        raise ValueError("The temporary folder resolves to a drive root, home, or the working folder.")
    root_info = root.stat()
    owner = os.getuid() if hasattr(os, "getuid") else None
    candidates = []
    for path in sorted(root.iterdir()):
        if path.suffix.casefold() not in {".tmp", ".temp"}:
            continue
        try:
            info = path.lstat()
        except OSError:
            continue
        if (
            stat.S_ISREG(info.st_mode)
            and not is_link_or_reparse(info)
            and (owner is None or info.st_uid == owner)
            and info.st_mtime < cutoff
        ):
            candidates.append((path, info))

    CONSOLE.print(literal(f"Temporary folder {root}"))
    if not candidates:
        CONSOLE.print("No matching temporary files.")
        return
    table = make_table("Deletion preview", "File", "Bytes")
    for path, info in candidates:
        table.add_row(literal(path.name), f"{info.st_size:,}")
    CONSOLE.print(table)
    if ask("Type DELETE to permanently remove the listed files, or press Enter to cancel") != "DELETE":
        CONSOLE.print("Cleanup canceled.")
        return

    current_root = root.stat()
    if root.resolve(strict=True) != root or (root_info.st_dev, root_info.st_ino) != (
        current_root.st_dev, current_root.st_ino
    ):
        raise ValueError("The temporary folder changed after the preview.")
    deleted = 0
    reclaimed = 0
    for path, previous in candidates:
        try:
            current = path.lstat()
            if current != previous or current.st_mtime_ns != previous.st_mtime_ns or is_link_or_reparse(current):
                continue
            path.unlink()
        except OSError:
            continue
        deleted += 1
        reclaimed += previous.st_size
    CONSOLE.print(f"Deleted {deleted} files ({reclaimed:,} bytes). Skipped {len(candidates) - deleted}.")


def nebula_project_sites() -> None:
    root = ask_file("Project directory").resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Choose a project directory.")
    ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
    pages = 0
    items = []
    for folder, directories, files in os.walk(root):
        here = Path(folder)
        children = []
        for name in sorted(directories):
            if name.casefold() in ignored or name.startswith("."):
                continue
            try:
                info = (here / name).lstat()
            except OSError:
                continue
            tag = getattr(info, "st_reparse_tag", 0)
            if stat.S_ISDIR(info.st_mode) and tag != getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", None):
                children.append(name)
        directories[:] = children
        for name in sorted(files):
            path = here / name
            if path.suffix.casefold() in {".htm", ".html"}:
                pages += 1
                if len(items) < 50:
                    items.append(path.relative_to(root))
    if not pages:
        CONSOLE.print("No HTML source files found in this project directory.")
        return

    table = make_table(f"Local HTML files · showing {len(items)} of {pages}", "Project-relative path")
    for path in items:
        table.add_row(literal(path))
    CONSOLE.print(table)


def nebula_site_list() -> None:
    default_path = Path(__file__).with_name("sites.txt")
    path = ask_file("UTF-8 text file with one site per line", default=str(default_path), show_default=False)
    sites = {}
    with path.open(encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                parts = urlsplit(normalize_http_url(value))
            except ValueError:
                raise ValueError(f"Invalid site on line {line_number}.") from None
            site = parts._replace(query="", fragment="").geturl()
            sites[site] = parts.hostname
    if not sites:
        CONSOLE.print("The file contains no sites.")
        return

    table = make_table("Imported site list", "Hostname", "URL")
    for site, hostname in sites.items():
        table.add_row(literal(hostname), literal(site))
    CONSOLE.print(table)


def nebula_report_summary() -> None:
    path = ask_file("Saved Web Vulnerability Scanner TXT or TelaScan JSON report")
    counts = {}
    if path.suffix.casefold() == ".json":
        data = load_json(path)
        summary = data.get("Resumo") if isinstance(data, dict) else None
        if not isinstance(summary, dict):
            raise ValueError("The TelaScan JSON report is missing its Resumo section.")
        for key, label in (("Critico", "Critical"), ("Alto", "High"), ("Medio", "Medium"), ("Info", "Informational")):
            value = summary.get(key)
            if type(value) is not int or value < 0:
                raise ValueError("A TelaScan severity count is missing or invalid.")
            counts[label] = value
    else:
        with path.open(encoding="utf-8-sig") as source:
            for line in source:
                if line.strip() == "FINDINGS BY SEVERITY":
                    break
            for line in source:
                match = re.fullmatch(r"\s*(Critical|High|Medium|Low|Informational)\s*:\s*([0-9]+)\s*", line)
                if not match:
                    break
                counts[match[1]] = int(match[2])
        if set(counts) != {"Critical", "High", "Medium", "Low", "Informational"}:
            raise ValueError("The report is missing a complete FINDINGS BY SEVERITY section.")

    table = make_table("Assessment report summary", "Severity", "Count")
    for label, count in counts.items():
        table.add_row(label, str(count))
    table.add_row("Total", str(sum(counts.values())))
    CONSOLE.print(table)


def nebula_disk_usage() -> None:
    path = ask_file("File or directory on the volume, or press Enter for the current directory", default=".", show_default=False)
    path = path.resolve(strict=True)
    usage = shutil.disk_usage(path.parent if path.is_file() else path)
    table = make_table("Disk usage", "Field", "Value")
    table.add_row("Location", literal(path))
    table.add_row("Capacity", f"{usage.total:,} bytes")
    table.add_row("Used", f"{usage.used:,} bytes")
    table.add_row("Free", f"{usage.free:,} bytes")
    CONSOLE.print(table)


def nebula_local_html() -> None:
    path = ask_file("Local HTML file")
    with path.open("rb") as source:
        data = source.read(MAX_HTML_BYTES + 1)
    if len(data) > MAX_HTML_BYTES:
        raise ValueError("The HTML file exceeds the 2 MB size limit.")
    soup = BeautifulSoup(data, "html.parser")
    table = make_table("Local HTML summary", "Field", "Value")
    table.add_row("Title", literal(soup.title.get_text(" ", strip=True) if soup.title else "Not provided"))
    table.add_row("Links", str(len(soup.find_all("a", href=True))))
    table.add_row("Forms", str(len(soup.find_all("form"))))
    table.add_row("Script tags", str(len(soup.find_all("script"))))
    table.add_row("Images without alt attribute", str(len(soup.find_all("img", alt=False))))
    CONSOLE.print(table)


def nebula_dns_resolver() -> None:
    resolver = dns.resolver.Resolver()
    table = make_table("System DNS resolver", "Field", "Value")
    for server in resolver.nameservers:
        table.add_row("Nameserver", literal(server))
    table.add_row("Resolver port", str(resolver.port))
    table.add_row("Resolver timeout (seconds)", str(resolver.timeout))
    CONSOLE.print(table)


def read_bounded_file(path: Path, limit: int) -> bytes:
    if not path.is_file():
        raise ValueError("Choose a regular file.")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"The selected file exceeds the {limit // (1024 * 1024)} MiB limit.")
    return data


def write_new_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def nebula0crip_transform(data: bytes, passphrase: str, *, decrypt: bool = False) -> bytes:
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise ValueError("Install the encryption dependency with python -m pip install cryptography.") from None

    # Format v1 is magic/version, 16-byte salt, 12-byte nonce, ciphertext, and 16-byte tag.
    # Scrypt v1 parameters are fixed so older files remain readable.
    if decrypt:
        if not data.startswith(CRIP_MAGIC) or len(data) < CRIP_HEADER_SIZE + CRIP_TAG_SIZE:
            raise ValueError("This is not a complete Nebula0Crip v1 file.")
        header = data[:CRIP_HEADER_SIZE]
        salt = header[len(CRIP_MAGIC):len(CRIP_MAGIC) + CRIP_SALT_SIZE]
        nonce = header[-CRIP_NONCE_SIZE:]
    else:
        salt = secrets.token_bytes(CRIP_SALT_SIZE)
        nonce = secrets.token_bytes(CRIP_NONCE_SIZE)
        header = CRIP_MAGIC + salt + nonce

    key = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(passphrase.encode("utf-8"))
    cipher = AESGCM(key)
    if decrypt:
        try:
            return cipher.decrypt(nonce, data[CRIP_HEADER_SIZE:], header)
        except InvalidTag:
            raise ValueError("Decryption failed. The passphrase is incorrect or the file was changed.") from None
    return header + cipher.encrypt(nonce, data, header)


def nebula0crip_encrypt() -> None:
    source = ask_file("File to encrypt")
    default_output = source.with_name(source.name + ".nebula0crip")
    destination = ask_file("New encrypted file", default=str(default_output))
    data = read_bounded_file(source, CRIP_MAX_BYTES)
    passphrase = ask_secret("New passphrase (at least 12 characters)")
    if len(passphrase) < 12:
        raise ValueError("Use at least 12 characters for the passphrase.")
    confirmation = ask_secret("Confirm passphrase")
    if not hmac.compare_digest(passphrase.encode("utf-8"), confirmation.encode("utf-8")):
        raise ValueError("The passphrases do not match.")
    write_new_file(destination, nebula0crip_transform(data, passphrase))
    CONSOLE.print(literal(f"Encrypted copy saved to {destination}"), style="green")


def nebula0crip_decrypt() -> None:
    source = ask_file("Nebula0Crip file to decrypt")
    basename = source.name.removesuffix(".nebula0crip")
    default_output = source.with_name(f"{basename}.decrypted")
    destination = ask_file("New decrypted file", default=str(default_output))
    data = read_bounded_file(source, CRIP_MAX_BYTES + CRIP_HEADER_SIZE + CRIP_TAG_SIZE)
    passphrase = ask_secret("Passphrase")
    write_new_file(destination, nebula0crip_transform(data, passphrase, decrypt=True))
    CONSOLE.print(literal(f"Decrypted copy saved to {destination}"), style="green")


def nebula_ip_check() -> None:
    address = ipaddress.ip_address(ask("IPv4 or IPv6 address"))
    private_ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") if address.version == 4 else ("fc00::/7",)
    table = make_table("IP address properties", "Property", "Value")
    table.add_row("Address", str(address))
    table.add_row("Version", f"IPv{address.version}")
    for label, enabled in (
        ("Global range (Python classification)", address.is_global),
        ("Private-use range", any(address in ipaddress.ip_network(network) for network in private_ranges)),
        ("IPv4 shared range (CGNAT)", address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10")),
        ("Loopback", address.is_loopback),
        ("Link-local", address.is_link_local),
        ("Multicast", address.is_multicast),
        ("Unspecified", address.is_unspecified),
        ("Reserved", address.is_reserved),
    ):
        table.add_row(label, "Yes" if enabled else "No")
    CONSOLE.print(table)


def nebula_public_ip() -> None:
    with requests.get(
        PUBLIC_IP_URL, params={"format": "json"}, timeout=HTTP_TIMEOUT, allow_redirects=False
    ) as response:
        if response.status_code != 200:
            raise ValueError(f"ipify returned HTTP {response.status_code}.")
        data = response.json()
    if not isinstance(data, dict) or not isinstance(data.get("ip"), str):
        raise ValueError("ipify returned an unexpected response format.")
    address = ipaddress.ip_address(data["ip"])
    CONSOLE.print(literal(f"Public IPv{address.version} as seen by ipify: {address}"))


def nebula_ip_reverse() -> None:
    address = ipaddress.ip_address(ask("IPv4 or IPv6 address"))
    resolver = dns.resolver.Resolver()
    table = make_table("Reverse DNS", "IP address", "PTR name")
    for record in query_dns(resolver, address.reverse_pointer, "PTR"):
        table.add_row(str(address), literal(record))
    CONSOLE.print(table)


def nebula_nmap_report() -> None:
    path = ask_file("Saved Nmap XML report")
    data = read_bounded_file(path, 5 * 1024 * 1024).decode("utf-8-sig")
    data = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", data, count=1)
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.IGNORECASE):
        raise ValueError("The report contains unsupported XML declarations.")
    report = ET.fromstring(data)
    if report.tag != "nmaprun":
        raise ValueError("Choose an Nmap XML report with an nmaprun root.")

    table = make_table("Nmap report", "Address", "Port", "State", "Service")
    hosts = report.findall("host")
    for host in hosts:
        addresses = [
            node.get("addr") for node in host.findall("address")
            if node.get("addrtype") in {"ipv4", "ipv6"} and node.get("addr")
        ]
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            port_label = f"{port.get('portid', '?')}/{port.get('protocol', '?')}"
            table.add_row(
                literal(", ".join(addresses) or "Unknown"),
                literal(port_label),
                literal(state.get("state", "Unknown") if state is not None else "Unknown"),
                literal(service.get("name", "Unknown") if service is not None else "Unknown"),
            )
    CONSOLE.print(f"Host entries ({len(hosts)}) · Port entries ({table.row_count})")
    if table.row_count:
        CONSOLE.print(table)


def nebula_secure_key() -> None:
    size = ask("Random bytes", choices=["16", "24", "32", "64"], default="32")
    output = ask("Encoding", choices=["hex", "url-safe"], default="hex")
    key = secrets.token_hex(int(size)) if output == "hex" else secrets.token_urlsafe(int(size))
    CONSOLE.print(Text(key, no_wrap=True, overflow="ignore"))


def nebula_base64() -> None:
    mode = ask("Mode", choices=["encode", "decode"], default="encode")
    value = CONSOLE.input("Text: " if mode == "encode" else "Base64: ")
    if mode == "encode":
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        CONSOLE.print(Text(encoded, no_wrap=True, overflow="ignore"))
        return
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        raise ValueError("Enter valid standard Base64 that represents UTF-8 text.") from None
    CONSOLE.print(literal(decoded if decoded.isprintable() else repr(decoded)))


def nebula_hmac_file() -> None:
    path = ask_file("File to authenticate")
    key_text = ask_secret("Hex key (64 characters)")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", key_text):
        raise ValueError("Enter a 32-byte key in hexadecimal, such as one from Secure Key Generator.")
    key = bytes.fromhex(key_text)
    expected = ask("Expected HMAC, or press Enter to compute only", default="", show_default=False).lower()
    if expected and not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("An HMAC-SHA256 tag must be 64 hexadecimal characters.")
    if not path.is_file():
        raise ValueError("Choose a regular file.")
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, lambda: hmac.new(key, digestmod="sha256")).hexdigest()
    CONSOLE.print(literal(f"HMAC-SHA256 {digest}"))
    if expected:
        matches = hmac.compare_digest(digest, expected)
        CONSOLE.print("HMAC matches." if matches else "HMAC mismatch.", style="green" if matches else "red")


def nebula_website_profile() -> None:
    url = ask_url()
    table = make_table("Website profile", "Field", "Value")
    with requests.get(url, timeout=HTTP_TIMEOUT, stream=True) as response:
        content_type = response.headers.get("Content-Type", "")
        table.add_row("HTTP status", str(response.status_code))
        table.add_row("Final URL", literal(response.url))
        table.add_row("Content type", literal(content_type or "Not provided"))
        table.add_row("Redirects", str(len(response.history)))
        if content_type.partition(";")[0].strip().lower() in {"text/html", "application/xhtml+xml", ""}:
            soup = parse_html_response(response)
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            description_tag = soup.find("meta", attrs={"name": re.compile(r"^description$", re.IGNORECASE)})
            description = description_tag.get("content", "") if description_tag else ""
            canonical_tag = soup.find("link", rel="canonical", href=True)
            canonical_url = resolve_http_url(response.url, canonical_tag["href"]) if canonical_tag else None
            table.add_row("Title", literal(title[:300] or "Not provided"))
            table.add_row("Description", literal(description[:300] or "Not provided"))
            table.add_row("Canonical URL", literal(canonical_url or "Not provided"))
    CONSOLE.print(table)


def nebula_image_exif() -> None:
    try:
        from PIL import ExifTags, Image
    except ImportError:
        raise ValueError("Install the EXIF dependency with python -m pip install Pillow.") from None

    path = ask_file("Local image file")
    if not path.is_file():
        raise ValueError("Choose a regular image file.")
    table = make_table("Image metadata", "Field", "Value")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                table.add_row("Format", literal(image.format or "Unknown"))
                table.add_row("Dimensions", f"{image.width} × {image.height}")
                exif = image.getexif()
                table.add_row("EXIF", "Present" if exif else "Not present")
                if exif:
                    detail = exif.get_ifd(ExifTags.IFD.Exif)
                    for label, value in (
                        ("Camera make", exif.get(ExifTags.Base.Make)),
                        ("Camera model", exif.get(ExifTags.Base.Model)),
                        ("Orientation", exif.get(ExifTags.Base.Orientation)),
                        ("Date taken", detail.get(ExifTags.Base.DateTimeOriginal) or exif.get(ExifTags.Base.DateTime)),
                    ):
                        if value is not None:
                            table.add_row(label, literal(str(value)[:300]))
                    table.add_row("GPS metadata", "Present" if ExifTags.IFD.GPSInfo in exif else "Not present")
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as error:
        raise ValueError("The image exceeds Pillow's pixel safety threshold.") from error
    CONSOLE.print(table)


def nebula_ip_ping() -> None:
    address = ipaddress.ip_address(ask("Single IPv4 or IPv6 address"))
    scope = getattr(address, "scope_id", None)
    if scope is not None and not re.fullmatch(r"[A-Za-z0-9_.-]+", scope):
        raise ValueError("The IPv6 scope identifier contains unsupported characters.")
    if os.name == "nt":
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        command = [str(system_root / "System32" / "PING.EXE"), "-n", "1", "-w", "2000"]
    else:
        mac_ipv6 = sys.platform == "darwin" and address.version == 6
        ping = shutil.which("ping6" if mac_ipv6 else "ping")
        if not ping:
            raise ValueError("The system ping command is unavailable.")
        command = [ping, "-n", "-c", "1"]
        if address.version == 6 and not mac_ipv6:
            command.append("-6")

    result = subprocess.run(
        [*command, str(address)],
        capture_output=True,
        text=True,
        encoding="oem" if os.name == "nt" else None,
        errors="replace",
        timeout=6,
    )
    CONSOLE.print(f"Ping exit code {result.returncode}")
    for line in (result.stdout or result.stderr).splitlines():
        if line.strip():
            CONSOLE.print(literal(line))


def nebula_example_ips() -> None:
    version = ask("IP version", choices=["4", "6"], default="4")
    count = ask("How many example addresses", default="5")
    if not re.fullmatch(r"[0-9]{1,2}", count) or not 1 <= int(count) <= 20:
        raise ValueError("Choose between 1 and 20 example addresses.")
    if version == "4":
        network = ipaddress.ip_network("192.0.2.0/24")
        offsets = range(1, 255)
    else:
        network = ipaddress.ip_network("2001:db8::/32")
        offsets = range(1, 65536)
    table = make_table("Documentation example addresses", "Address")
    for offset in secrets.SystemRandom().sample(offsets, int(count)):
        table.add_row(str(network.network_address + offset))
    CONSOLE.print(table)


def nebula_sqlite_search() -> None:
    path = ask_file("Local SQLite database").resolve(strict=True)
    if not path.is_file():
        raise ValueError("Choose a regular SQLite database file.")

    with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True, timeout=2)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        tables = [
            row[1] for row in db.execute("PRAGMA main.table_list")
            if row[2] == "table" and not row[1].startswith("sqlite_")
        ]
        if not tables:
            CONSOLE.print("No ordinary tables found in this database.")
            return
        CONSOLE.print(literal("Tables · " + ", ".join(tables)))
        table_name = ask("Table name", choices=tables, show_choices=False)
        columns = [
            row[0] for row in db.execute("SELECT name FROM pragma_table_xinfo(?, 'main') WHERE hidden = 0", (table_name,))
        ]
        if not columns:
            CONSOLE.print("The selected table contains no searchable columns.")
            return
        CONSOLE.print(literal("Columns · " + ", ".join(columns)))
        column = ask("Text column", choices=columns, show_choices=False)
        needle = ask("Text to find (case-sensitive)")
        if not needle:
            raise ValueError("Enter text to search for.")
        quoted_table = '"' + table_name.replace('"', '""') + '"'
        quoted_column = '"' + column.replace('"', '""') + '"'
        deadline = time.monotonic() + 5
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 5000)
        results = db.execute(
            f"SELECT substr({quoted_column}, 1, 160) FROM main.{quoted_table} "
            f"WHERE typeof({quoted_column}) = 'text' AND instr({quoted_column}, ?) > 0 LIMIT 21",
            (needle,),
        ).fetchall()

    if not results:
        CONSOLE.print("No matches found.")
        return
    table = make_table("SQLite text matches", "Value preview")
    table.columns[0].min_width = 19
    for (value,) in results[:20]:
        table.add_row(literal(value))
    CONSOLE.print(table)
    if len(results) > 20:
        CONSOLE.print("Showing the first 20 matches.")


def nebula_password_hash() -> None:
    mode = ask("Action", choices=["create", "verify"], default="create")
    if mode == "create":
        salt = secrets.token_bytes(16)
    else:
        record = ask("Nebula scrypt record")
        parsed = re.fullmatch(r"nebula-scrypt-v1\$([0-9a-f]{32})\$([0-9a-f]{64})", record)
        if not parsed:
            raise ValueError("Enter a complete nebula-scrypt-v1 record.")
        salt = bytes.fromhex(parsed[1])
        expected = bytes.fromhex(parsed[2])

    password = ask_secret("Password")
    if not password:
        raise ValueError("Enter a password.")
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1, maxmem=160 * 1024 * 1024, dklen=32
    )
    if mode == "create":
        record = "$".join(("nebula-scrypt-v1", salt.hex(), digest.hex()))
        CONSOLE.print(Text(record, no_wrap=True, overflow="ignore"))
    elif hmac.compare_digest(digest, expected):
        CONSOLE.print("Password matches.", style="green")
    else:
        CONSOLE.print("Password does not match.", style="red")


def run_module(action: Callable[[], None]) -> None:
    try:
        action()
    except requests.RequestException as error:
        CONSOLE.print(literal(f"HTTP request failed. {error}"), style="red")
    except (OSError, ValueError, SyntaxError, csv.Error, dns.exception.DNSException, sqlite3.Error, subprocess.SubprocessError) as error:
        CONSOLE.print(literal(f"Unable to complete the check. {error}"), style="red")
    except KeyboardInterrupt:
        CONSOLE.print("\nCheck interrupted.", style="yellow")


def main_menu() -> None:
    groups = (
        ("DNS & advisories", (
            ("1", "DNS & WHOIS", "Looks up DNS records and public registration details for a domain or URL.", nebula_recon),
            ("6", "Subdomain DNS Check", "Looks up IPv4 and IPv6 addresses for full hostnames in your inventory.", nebula_subdomain),
            ("7", "CVE Lookup", "Searches the NVD by product or version and shows up to five published records.", nebula_cve),
            ("8", "DNS Policy Records", "Displays published email, certificate issuance, and DNSSEC delegation records.", nebula_dns_policy),
            ("32", "DNS Resolver Settings", "Shows the system DNS servers, port, and timeout without doing a lookup.", nebula_dns_resolver),
        )),
        ("IP & network reports", (
            ("35", "IP Address Checker", "Classifies a supplied IPv4 or IPv6 address locally.", nebula_ip_check),
            ("36", "Public IP Address", "Asks ipify which public address this connection uses.", nebula_public_ip),
            ("37", "Nmap XML Review", "Displays hosts, ports, and service labels from an existing Nmap XML report.", nebula_nmap_report),
            ("41", "IP Reverse DNS", "Looks up the PTR hostname associated with one supplied IP address.", nebula_ip_reverse),
            ("44", "IP Ping", "Sends one ICMP ping to the supplied IPv4 or IPv6 address.", nebula_ip_ping),
            ("45", "Example IP Generator", "Generates IPv4 or IPv6 addresses from documentation networks for examples.", nebula_example_ips),
        )),
        ("Web", (
            ("2", "Security Headers", "Checks the final response for HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.", nebula_headers),
            ("3", "Page Links & Forms", "Lists links and form destinations from one page. Forms are never submitted.", nebula_crawler),
            ("9", "TLS Certificate", "Verifies the HTTPS certificate and shows its issuer, expiry, and fingerprint.", nebula_tls),
            ("10", "Cookie Attributes", "Shows Secure, HttpOnly, and SameSite on the first response. Cookie values stay hidden.", nebula_cookies),
            ("11", "Redirect Chain", "Follows redirects from one URL and highlights jumps from HTTPS to HTTP.", nebula_redirects),
            ("42", "Website Profile", "Shows the status, content type, title, and metadata of one webpage.", nebula_website_profile),
        )),
        ("Local files & inventory", (
            ("4", "Route Inventory Diff", "Compares approved and published URL paths from two text files.", nebula_fuzzer),
            ("5", "Local TCP Listeners", "Lists TCP ports in use by listeners on this computer.", nebula_port_scan),
            ("12", "File Integrity", "Computes a file hash and optionally checks it against an expected digest.", nebula_file_integrity),
            ("13", "JSON Config Drift", "Shows which top-level JSON keys changed while keeping their values private.", nebula_config_diff),
            ("14", "Python Source Review", "Flags selected Python calls for review by reading source without executing it.", nebula_python_review),
            ("15", "HTTP Log Summary", "Counts request methods and status codes from a comma-delimited log with a header.", nebula_http_log_summary),
            ("18", "JSON Validator", "Validates JSON syntax, checks for duplicate keys, and reports the top-level type.", nebula_json_validator),
            ("19", "CSV Inspector", "Lists CSV columns and counts rows with missing or extra fields.", nebula_csv_inspector),
            ("20", "File Metadata", "Shows file size, modification time, and a media type inferred from the name.", nebula_file_metadata),
            ("43", "Image EXIF", "Reads camera, image, and date metadata locally. GPS coordinates stay hidden.", nebula_image_exif),
            ("46", "SQLite Text Search", "Searches one text column in a local SQLite database opened read-only.", nebula_sqlite_search),
        )),
        ("Projects & maintenance", (
            ("26", "Temporary File Cleanup", "Previews old .tmp and .temp files in the temporary folder and removes the listed files after confirmation.", nebula_temp_cleanup),
            ("27", "Project Site Inventory", "Lists HTML files in a project directory, excluding build output and dependency folders.", nebula_project_sites),
            ("28", "Site List Import", "Reads a text file with one site per line and displays the URLs without query values.", nebula_site_list),
            ("29", "Assessment Report Summary", "Counts findings by severity in an existing Web Vulnerability Scanner or TelaScan report.", nebula_report_summary),
            ("30", "Disk Usage", "Shows the capacity, used space, and free space on the selected volume.", nebula_disk_usage),
            ("31", "Local HTML Review", "Counts links, forms, scripts, and images missing alt text in a local HTML file.", nebula_local_html),
        )),
        ("Breach checks", (
            ("24", "Email Breach Check", "Opens Have I Been Pwned without a key. An API key enables optional in-terminal lookup.", nebula_email_breaches),
            ("25", "Password Exposure Check", "Checks Pwned Passwords using only the first five characters of a locally computed hash.", nebula_password_exposure),
        )),
        ("Offline utilities", (
            ("16", "URL Inspector", "Breaks a URL into its hostname, port, path, and query names without requesting it.", nebula_url_inspector),
            ("17", "CIDR Calculator", "Calculates the network, address boundaries, and size of an IPv4 or IPv6 prefix.", nebula_cidr),
            ("21", "HTTP Status Reference", "Looks up the standard phrase and meaning for an HTTP status code.", nebula_http_status),
            ("22", "Timestamp Converter", "Converts between Unix seconds and a UTC ISO timestamp for comparing logs.", nebula_timestamp),
            ("23", "Password Generator", "Generates a random password locally with letters, digits, and symbols.", nebula_password),
            ("39", "Base64 Text", "Encodes and decodes UTF-8 text as Base64.", nebula_base64),
        )),
        ("Cryptography", (
            ("33", "Nebula0Crip Encrypt", "Creates an authenticated encrypted copy of one file using your passphrase.", nebula0crip_encrypt),
            ("34", "Nebula0Crip Decrypt", "Authenticates a .nebula0crip file and saves its contents as a new file.", nebula0crip_decrypt),
            ("38", "Secure Key Generator", "Generates a random key or token in hexadecimal or URL-safe text.", nebula_secure_key),
            ("40", "HMAC-SHA256 File", "Creates or verifies a file authentication tag using a shared key.", nebula_hmac_file),
            ("47", "Password Hash", "Creates or verifies a salted scrypt record for one password.", nebula_password_hash),
        )),
    )
    tools_by_number = {}
    panels = []
    for title, options in groups:
        menu = Text()
        for index, (key, label, description, action) in enumerate(options):
            if index:
                menu.append("\n")
            menu.append(f"[{key}]".ljust(5), style=f"bold {PURPLE}")
            menu.append(label)
            tools_by_number[key] = (label, description, action)
        panels.append(Panel.fit(menu, title=title, border_style=PURPLE))

    try:
        while True:
            show_logo()
            CONSOLE.print(Columns(panels, padding=(0, 1), equal=True))
            CONSOLE.print(Text.assemble(("[?]", PURPLE), " Tool guide    ", ("[0]", PURPLE), " Exit"))
            choice = ask("Select a tool", choices=[*tools_by_number, "?", "0"], show_choices=False)
            if choice == "0":
                break
            if choice == "?":
                guide = make_table("Tool guide", "No.", "Tool", "What it does")
                for key in sorted(tools_by_number, key=int):
                    label, description, _ = tools_by_number[key]
                    guide.add_row(key, label, description)
                CONSOLE.print(guide)
            else:
                label, description, action = tools_by_number[choice]
                CONSOLE.print(Panel(description, title=label, border_style=PURPLE))
                run_module(action)
            ask("\nPress Enter to return to the menu", default="", show_default=False)
    except (EOFError, KeyboardInterrupt):
        CONSOLE.print()
    CONSOLE.print("Nebula Arsenal closed.", style=PURPLE)


if __name__ == "__main__":
    if not confirm_usage():
        raise SystemExit(1)
    main_menu()
