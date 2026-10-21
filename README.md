# OSINT Domain Analyzer

A Python tool that collects **publicly available information** about a domain
name and produces an **explainable risk score (0-100)**. It is built to help a
SOC analyst quickly triage a suspicious domain, and it shows the
reconnaissance step used in penetration testing.

> Uses only public data (WHOIS, DNS, IP geolocation). No active scanning or
> attacks. For authorized and lawful use only.

## Problem it solves

When a suspicious link or email arrives, an analyst has to check many things on
many different websites: how old is the domain, where does it point, can its
email be spoofed. This tool does these checks in one step and explains every
point of the score, so the analyst can decide quickly.

## Features

- **Input validation:** only well-formed public domain names are accepted
  (URLs, IP addresses, localhost and internal names are rejected).
- **WHOIS:** registrar, creation and expiry date, name servers, domain age.
- **DNS records:** A, AAAA, MX, NS, TXT (fixed public resolvers 8.8.8.8 and
  1.1.1.1 so results are consistent).
- **Email security:** SPF and DMARC policy analysis.
- **IP information:** country, city, ISP and ASN (public IPs only).
- **Explainable risk score:** every point comes with a reason. Data that could
  not be collected is listed as *unknown* and is never counted as risk.
- **Dashboard (Flask):** scan form, report page, scan history.
- **Logs and export:** every scan is stored in SQLite; export a report as JSON
  and the history as CSV.

## How it works

```
Input -> validator -> WHOIS / DNS / Email security / IP lookup
      -> risk engine (score + reasons) -> scanner -> SQLite + Flask dashboard
```

| File | Purpose |
|------|---------|
| `osint/validator.py` | Cleans and validates the domain (allow-list approach) |
| `osint/whois_lookup.py` | WHOIS data, domain age, retry and clean errors |
| `osint/dns_lookup.py` | DNS records using fixed public resolvers |
| `osint/email_security.py` | SPF and DMARC checks |
| `osint/ip_lookup.py` | IP geolocation (private IPs are refused) |
| `osint/risk_engine.py` | Explainable risk scoring and severity |
| `osint/scanner.py` | Runs all modules and builds one report |
| `osint/database.py` | SQLite history (parameterized queries) |
| `app.py` | Flask dashboard and exports |
| `test_osint.py` | Offline unit tests |

## Risk scoring

| Indicator | Points |
|-----------|--------|
| Domain younger than 30 / 90 / 365 days | 35 / 20 / 10 |
| Domain does not exist (NXDOMAIN) | 30 |
| No A or AAAA record | 15 |
| No MX record | 5 |
| SPF missing / neutral / softfail / allow-all | 15 / 15 / 5 / 20 |
| DMARC missing / monitor-only (p=none) | 15 / 10 |

Severity: **Low** (0-24), **Medium** (25-49), **High** (50-74),
**Critical** (75-100).

## Installation

```
git clone https://github.com/prathameshghavre/osint-domain-analyzer.git
cd osint-domain-analyzer
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
python app.py
```

Open `http://127.0.0.1:5000` in a browser, enter a domain such as
`example.com` and click **Scan**.

Run the tests:

```
python -m unittest test_osint -v
```

## Security of the tool itself

- Strict input validation before any lookup
- SQL queries use `?` placeholders (protection against SQL injection)
- Jinja2 auto-escaping in templates (protection against XSS)
- Security headers, request size limit, `debug=False`
- Server listens on `127.0.0.1` only
- Lookups only for public IP addresses; local requests have timeouts

## Testing

| # | Test | Expected | Actual |
|---|------|----------|--------|
| 1 | Valid domain `example.com` | Accepted | Pass |
| 2 | `localhost`, `192.168.1.1`, URL, `bad_domain.com`, empty, `-abc.com` | Rejected | Pass |
| 3 | SQL-injection text and `<script>` as input | Rejected | Pass |
| 4 | Dashboard input `http://bad input` | Error shown, nothing saved | Pass |
| 5 | Live scan `google.com` | Low risk, SPF softfail, DMARC reject | Pass |
| 6 | Live scan `example.com` | Score 0, SPF strict | Pass |
| 7 | Live scan of a non-existent domain | Score 30, email checks "not applicable" | Pass |
| 8 | Private IP `192.168.0.1` | Lookup skipped with error | Pass |
| 9 | Simulated new domain with weak email | High (70) | Pass |
| 10 | Simulated new domain with no IP | Critical (85) | Pass |
| 11 | Simulated unknown domain age / failed DMARC lookup | Counted as unknown, not risk | Pass |
| 12 | CSV export of history | File downloads with all rows | Pass |

Tests 1-3 and 9-11 are automated (`test_osint.py`, 8 tests). The High and
Critical cases use **simulated data**, not real phishing domains.

## Limitations

- The point values in the risk score are heuristic weights chosen for this
  project. They are indicators, **not a final verdict**, and false positives
  and false negatives are possible.
- WHOIS servers sometimes rate-limit or return empty answers. The tool retries
  once and then reports the data as unknown.
- DNS answers can differ by location and time (for example geo-based IPs).
- IP geolocation depends on a free online API (`ipwho.is`) and may be
  inaccurate or unavailable.
- Only the first A record is used for IP lookup.
- It is a local development server, not meant for production use.

## Possible future work

- Look-alike (typosquatting) domain detection
- Batch scanning of a domain list
- Login for the dashboard
- Connect with honeypot logs to investigate attacker IPs

## Author

Prathamesh Ghavre - [GitHub](https://github.com/prathameshghavre)