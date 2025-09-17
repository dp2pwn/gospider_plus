# GoSpider++

GoSpider++ is an advanced, stealth-focused web crawler maintained by the [w3b_pwn team](https://t.me/w3b_pwn). It augments the original GoSpider engine with evasive networking profiles, JavaScript-aware discovery, and reflection hunting so security researchers can map application attack surfaces quickly without triggering noisy defenses.

## Table of contents
- [Overview](#overview)
- [Feature highlights](#feature-highlights)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage guide](#usage-guide)
- [Advanced modules](#advanced-modules)
- [CLI cheat sheet](#cli-cheat-sheet)
- [Development](#development)
- [License](#license)
- [Credits and community](#credits-and-community)

## Overview

GoSpider++ focuses on three goals:

1. **Coverage** – aggressively enumerate forms, links, and script-generated requests (including dynamically assembled endpoints) to expose hidden attack paths.
2. **Context** – enrich crawls with third-party archives, response metadata, and reflection analysis so findings are actionable without additional tooling.
3. **Stealth** – mimic real browser traffic through TLS/JA3 randomization, HTTP/2 tuning, rotating headers, and timing jitter to reduce WAF friction.

The project targets security teams, bug bounty hunters, and offensive researchers who need high-fidelity recon with minimal manual babysitting.

## Feature highlights

- **Anti-detection client** – `--stealth` activates randomized TLS, JA3, HTTP/2, headers, timing, and optional proxy rotation to blend into legitimate traffic.
- **JavaScript intelligence** – parses `.js` assets, detects fetch/XHR patterns, simulates requests, and resolves relative endpoints for deeper coverage.
- **Reflection detection** – `--reflected` and `--reflected-output` compare baseline and mutated requests to surface echoed payloads in real time.
- **Archive enrichment** – `--other-source`, `--include-subs`, and `--include-other-source` pull targets from Wayback Machine, Common Crawl, VirusTotal, and AlienVault.
- **Flexible output** – stream URLs, emit JSON, record raw metadata, filter by response length, and persist per-target logs via the `-o` flag.
- **Session reuse** – import Burp Suite requests, load custom headers, reuse cookies, and forward traffic through HTTP/S proxies.
- **Parallel crawling** – control recursion depth, concurrency, delay, and random jitter to match target fragility while scaling across host lists.

## Installation

> Requires Go 1.18 or newer when building from source.

### Go install (recommended)

```
go install github.com/w3b-pwn/gospider-plusplus@latest
```

This places the `gospider++` binary in your `$GOPATH/bin`.

### Build from source

```
git clone https://github.com/w3b-pwn/gospider-plusplus.git
cd gospider-plusplus
go build -o gospider++ ./
```

The resulting binary appears as `./gospider++` (or `gospider++.exe` on Windows).

### Docker

```
# build image
docker build -t gospider-plusplus:latest .

# show CLI help
docker run --rm -it gospider-plusplus:latest -h

# crawl a target with results saved locally
docker run --rm -it \
  -v $(pwd)/output:/data \
  gospider-plusplus:latest \
  -s https://example.com -o /data/example
```

### Windows build

```
go build -o gospider.exe ./
```

Pack the executable with your favourite installer or distribute alongside a config pack.

## Quick start

```
# Crawl a single site with moderate depth and concurrency
gospider++ -s https://target.com -d 2 -c 10 -o recon-output

# Feed multiple targets via file (or stdin) and enrich with archives
gospider++ -S targets.txt -t 15 -c 8 --other-source --include-other-source -o recon-output

# Stream JSON for automation pipelines
gospider++ -s https://target.com --json | jq -r '.output'
```

GoSpider++ creates one log per hostname inside the directory provided to `-o`.

## Usage guide

### Input options

- `-s, --site` – crawl a single URL.
- `-S, --sites` – crawl a newline-delimited file or use `-` to read from stdin.
- `-t, --threads` – number of targets processed in parallel.
- `-c, --concurrent` – per-domain request concurrency.
- `-d, --depth` – recursion depth (`0` for unlimited).
- `-k, --delay` / `-K, --random-delay` – throttle noisy jobs with fixed and random wait times.

### Output controls

- `--json` – emit machine-readable output with `input`, `source`, `type`, `output`, `status`, `length`, `param`, `payload` fields.
- `--quiet` – print URLs only.
- `--raw` – include status codes and body lengths for each finding.
- `--length` and `-L start,end` – collect or filter responses by size.
- `-o` – persist findings per host; combine with `--reflected-output` for dedicated reflection logs.

### Session & scope management

```
gospider++ -s https://target.com \
  --proxy http://127.0.0.1:8080 \
  --burp burp_req.txt \
  -H "Accept: */*" \
  --cookie "session=a1b2c3" \
  --whitelist-domain target.com \
  --blacklist ".(png|woff2|svg)$"
```

Burp exports provide baseline headers and cookies; additional `-H` flags override or extend them.

## Advanced modules

- **Stealth reconnaissance (`--stealth`)** – engage the anti-detection HTTP client, rotating browser fingerprints, timing, and proxies to survive WAF scrutiny.
- **JavaScript request synthesis** – GoSpider++ normalizes JS-generated requests, deduplicates them, and replays candidates alongside HTML-discovered links.
- **Reflection hunting (`--reflected`)** – injects a sentinel parameter, compares mutated responses, and flags echoed payloads (use `--reflected-output` to store findings).
- **Archive fusion (`--other-source`)** – fetches URLs from Archive.org, Common Crawl, VirusTotal, and AlienVault; `--include-subs` expands to subdomains, `--include-other-source` feeds results back into the queue.

## CLI cheat sheet

| Flag | Description | Tips |
| --- | --- | --- |
| `-s, --site` / `-S, --sites` | Seed targets (single URL, file, or stdin) | Combine with `-t` for parallel host processing |
| `-c, --concurrent` | Max concurrent requests per domain | Pair with `-k`/`-K` delays for fragile apps |
| `-d, --depth` | Recursion depth control | `0` for unlimited crawl depth |
| `--js` / `--base` | Enable or disable JS enrichment | `--base` switches to HTML-only mode |
| `--sitemap`, `--robots` | Explore sitemap and robots endpoints | `--robots` enabled by default |
| `--stealth` | Activate anti-detection client | Works best with `--proxy` and `--random-delay` |
| `--reflected`, `--reflected-output` | Detect reflected payloads | Specify a file path to log confirmed findings |
| `--json`, `--quiet`, `--raw` | Output formatting options | Stack with `-o` for structured reporting |
| `--subs`, `--whitelist-domain`, `--blacklist` | Scope controls | Mix regex allow/deny lists with domain limits |

Run `gospider++ --help` for the authoritative flag list.

## Development

1. Clone the repository and ensure Go modules are enabled.
2. Format code with `gofmt` before submitting changes.
3. Run tests with:

   ```
   go test ./...
   ```

4. For manual smoke tests, crawl a controlled target:

   ```
   go run . -s https://example.com -d 1 -c 5 -q
   ```

Contributions that enhance stealth strategies, detection accuracy, or performance are especially welcome.

## License

GoSpider++ is released under the MIT License. Refer to [`LICENSE`](LICENSE) for the full text.

## Credits and community

GoSpider++ is created and maintained by the [w3b_pwn team](https://t.me/w3b_pwn). It stands on the shoulders of the original GoSpider by [@j3ssiejjj](https://twitter.com/j3ssiejjj) and [@thebl4ckturtle](https://twitter.com/thebl4ckturtle).

Join the w3b_pwn Telegram channel for updates, support, and sneak peeks at upcoming tooling: https://t.me/w3b_pwn.
