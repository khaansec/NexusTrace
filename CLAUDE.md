# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NexusTrace is a Flask-based OSINT (Open Source Intelligence) analysis tool that aggregates multiple threat intelligence APIs into a unified web interface. It provides IP, domain, URL, file, hash, user agent, Windows Event ID, and Azure AD error code analysis.

## Development Commands

```bash
# Run development server (starts on 0.0.0.0:5050)
python main.py

# Run with Docker Compose (Flask on 5050, Nginx on 80)
docker-compose up -d

# Production server
gunicorn --bind 0.0.0.0:5050 --timeout 120 main:app

# Run integration tests (requires a running server on localhost:5000)
python app/tests/test_endpoints.py

# Download IPinfo MMDB for offline geolocation
python scripts/download_ipinfo_mmdb.py
```

## Architecture

**Layered Design:**
- **Routes Layer** (`app/routes/`): Blueprint-organized HTTP handlers. Each analysis type has its own route file.
- **Services Layer** (`app/services/`): Business logic and external API integrations. All third-party API calls happen here.
- **Utils Layer** (`app/utils/`): Cross-cutting concerns — `cache.py` (LRU + TTL), `rate_limiter.py` (sliding window), `logging.py` (rotating file).

**Application Factory:** `app/__init__.py` uses `create_app()`. Security is configured here: Flask-WTF CSRF protection, Flask-Talisman security headers/CSP. Blueprints are registered via `app/routes/__init__.py:register_routes()`.

**Unified Analysis Entry Point:** `POST /analyze` in `app/routes/home_routes.py` is the primary route. It auto-detects the indicator type (IP, domain, URL, MD5/SHA1/SHA256 hash, user agent string, UUID event ID, Azure error code) via regex matching and dispatches to the appropriate services.

**Key Services:**
- `ip_service.py`: VPNapi (primary), IPinfo/MMDB, Shodan, ProxyCheck, AbuseIPDB, AlienVault OTX
- `domain_service.py`: WHOIS, DNS records, SSL/TLS certificate analysis
- `url_service.py`: Security headers, redirect chains, technology detection (BuiltWith)
- `file_service.py` / `hash_service.py`: Malware analysis (Intezer, VirusTotal, MalwareBazaar, ThreatFox)
- `azure_error_service.py`: Azure AD / AADSTS error code lookup
- `event_service.py`: Windows Event ID lookup
- `user_agent_service.py`: User-agent string parsing

**Rate Limiting:** `RateLimiter` class in `app/utils/rate_limiter.py` uses a sliding window. Used as a context manager (`with limiter:`). Per-service limits: AlienVault 4 req/s, Shodan 1 req/s, others 2 req/s.

**Caching:** `@timed_lru_cache(seconds=1800)` in `app/utils/cache.py`. Thread-safe, 30-min TTL, max 1000 items. A background daemon thread clears expired caches every 30 minutes.

## API Endpoints

| Route | Purpose |
|-------|---------|
| `POST /analyze` | Unified analysis — auto-detects indicator type |
| `POST /api/ip/check_ip` | Single IP analysis (JSON body: `{"ip": "..."}`) |
| `POST /api/ip/check_ips` | Batch IP analysis (file upload: CSV/XLSX/TXT, returns CSV) |
| `POST /api/domain/check_domain` | Domain info lookup |
| `POST /api/domain/analyze` | Full domain/URL analysis |
| `POST /api/file/analyze_file` | File malware analysis |
| `POST /api/hash/check_hash` | Hash reputation lookup |
| `POST /api/azure_error/search` | Azure AD AADSTS error code lookup |
| `POST /api/event/search` | Windows Event ID lookup |
| `GET /api/health` | Health check |

**CSRF:** Flask-WTF CSRF protection is enabled globally. Browser form submissions include the token automatically via Jinja2. For programmatic POST requests, include the CSRF token in the `X-CSRFToken` header or `csrf_token` form field.

## Environment Variables

Required API keys in `.env`:
- `VPNAPI_KEY` — VPN/proxy detection (primary IP data source)
- `IPINFO_TOKEN` — IP geolocation
- `SHODAN_KEY` — Port scanning and banner data
- `ABUSEIPDB_KEY` — Abuse reporting
- `ALIENVAULT` — OTX threat intelligence (used for IPs, domains, and hashes)
- `INTEZER_KEY` — File/hash malware analysis
- `IP2WHOIS_KEY` — WHOIS lookups
- `SECRET_KEY` — Flask session secret (auto-generated if not set)
- `SECURE_COOKIES` — Set `true` when running behind HTTPS
- `MMDB_PATH` — Optional: path to IPinfo MMDB for offline geolocation

## Adding New Features

**New analysis service:**
1. Create service in `app/services/` with API logic; wrap cached functions with `@timed_lru_cache(seconds=1800)`
2. Add rate limiter instance using `RateLimiter(max_requests=N, time_window=timedelta(seconds=1))` and use as context manager
3. Create routes in `app/routes/` with a Flask Blueprint
4. Register blueprint in `app/routes/__init__.py:register_routes()`
5. Create template in `templates/` extending `base.html`
6. Optionally add indicator-type detection in `home_routes.py:analyze()`

## Frontend

- Jinja2 templates in `templates/` — `base.html` is the layout shell
- Tailwind CSS loaded from CDN; no build step required
- PWA-capable with service worker at `static/sw.js` (served via `main.py` at `/sw.js`)
- Embedded CyberChef v10.19.4 in `CyberChef_v10.19.4/` — served as static files
- Mobile-optimized (see MOBILE_OPTIMIZATION.md)
