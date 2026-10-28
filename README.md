# portscan

[![tests](https://github.com/Romankdk/port-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/Romankdk/port-scanner/actions/workflows/tests.yml)

A readable network security scanner written in pure Python (standard library only, Python 3.9+).

It finds open ports, works out what is really listening on them, checks HTTPS certificates,
names the devices on your network, and tells you what changed since the last scan, with a
plain-English **risk note** for every finding.

Its defensive companion is [logwatch](https://github.com/Romankdk/logwatch): this scanner shows
**which doors are open**; logwatch reads server logs to show **who is knocking on them**.

> **Only scan systems you own or have written permission to test.** Scanning other people's
> networks can be illegal and will often trigger their intrusion detection.

## Getting started

1. Install [Python 3.9+](https://www.python.org/downloads/) if you don't have it
   (macOS and Linux usually do; on Windows tick "Add Python to PATH").
2. Download this repo: **Code → Download ZIP** (then unzip), or
   `git clone https://github.com/Romankdk/port-scanner.git`
3. Open a terminal in the folder and run:

```bash
python3 -m portscan 127.0.0.1             # this computer
python3 -m portscan auto --discover       # every device on your Wi-Fi/network
```

On Windows, type `python` instead of `python3`. `auto` detects your network
(for example `192.168.1.0/24`); you can also type the range yourself.

## Features

| Feature | What it does |
|---|---|
| TCP scanning | Fast, concurrent connect scan of common ports, `--top` (1-1024), or any list/range |
| Home devices | Knows phone, smart TV/Chromecast, printer, camera and smart-home ports, and never sends probe data to printers (which would print it) |
| Service identification | Recognizes SSH, HTTP, FTP, SMTP, POP3, IMAP, VNC, Redis, Memcached, MySQL, PostgreSQL, AirPlay and Elasticsearch **from their responses**, so a database hiding on port 8080 is still caught |
| HTTPS/TLS checks | Expired or soon-to-expire certificates, self-signed or untrusted certificates, and servers still accepting TLS 1.0/1.1 |
| UDP scanning | `--udp`: DNS (open resolvers), SNMP (default `public` community), NTP, NetBIOS, TFTP, SSDP/UPnP and mDNS |
| Device names | "Romans-MacBook.local", "HP-PRINTER" via mDNS, NetBIOS and reverse DNS |
| Scan comparison | `--diff` saves each scan and reports new devices, newly opened ports, new certificate problems and closed ports |
| HTML report | `--html report.html`: a shareable, colour-coded page (light and dark mode) |
| Scheduled scans | `--schedule 09:00` runs the scan daily and sends a desktop notification when something changes |

## Usage

```bash
cd port-scanner

python3 -m portscan 127.0.0.1                         # your own machine, common ports
python3 -m portscan 127.0.0.1 --top --udp             # more TCP ports plus UDP services
python3 -m portscan auto --discover                   # every device on your network
python3 -m portscan 192.168.1.0/24 --discover         # same, with the range typed out
python3 -m portscan 192.168.1.0/24 --discover --html network.html
python3 -m portscan 192.168.1.0/24 --discover --diff  # what changed since last time?
python3 -m portscan localhost --min-risk high         # only high/critical findings
python3 -m portscan localhost --json -o report.json   # machine-readable output
python3 -m portscan --help
```

Or install it as a `portscan` command: `pip3 install -e .`

### Tracking changes

The first `--diff` run saves a baseline in `~/.portscan/history/`. Later runs compare with it:

```
Changes since the last scan (2026-10-28T13:38:38):
  + Romans-MacBook.local 8443/tcp: https-alt is now open
  ! nas.local 443/tcp: Certificate expires within 30 days
  - printer.local 23/tcp: telnet is no longer open
```

`+` new exposure, `!` new problem, `~` changed service, `-` closed, `v` fixed.
The exit code is `3` when something new is exposed, so scripts can react.
Scans where nothing responded (for example, the network was down) are never used as a baseline,
and a device that missed one scan is not reported as new when it returns.

### Daily scans

```bash
python3 -m portscan 192.168.1.0/24 --discover --schedule 09:00   # install (macOS launchd)
python3 -m portscan 192.168.1.0/24 --unschedule                  # remove
```

Each run compares with the previous one, writes `~/.portscan/latest.html`, logs to
`~/.portscan/schedule.log`, and pops up a notification if anything new is exposed.
On Linux it prints a `crontab` line to add instead.

## Port states

| State | Meaning |
|---|---|
| open | Something accepted the connection (TCP) or replied (UDP) |
| closed | The host replied "connection refused" / ICMP port unreachable |
| filtered | No answer before the timeout (firewall, host down, or a silent UDP service) |

## Exit codes

`0` ok, `1` runtime error, `2` bad arguments, `3` `--diff` found new exposure.

## Project layout

```
portscan/
  __main__.py     command-line interface
  scanner.py      target/port parsing, TCP scan, orchestration
  fingerprint.py  identify services from their responses
  tlscheck.py     certificate and protocol checks
  udp.py          UDP probes
  names.py        device names (mDNS, NetBIOS, reverse DNS)
  dnsutil.py      minimal DNS packet building/parsing
  history.py      saving scans and comparing them
  report.py       text, JSON and HTML reports
  schedule.py     daily scans (launchd / cron)
  notify.py       desktop notifications
  services.py     known ports, risk levels and notes
  results.py      result data types
tests/            unit and local-network tests (no internet needed)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limits

- IPv4 only.
- A UDP service that stays silent looks the same as a firewalled port ("filtered").
- TLS 1.0/1.1 detection depends on what your Python's TLS library can still negotiate.

## License

MIT. See [LICENSE](LICENSE).
