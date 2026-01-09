# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NexusTrace is a Flask-based OSINT (Open Source Intelligence) analysis tool that aggregates multiple threat intelligence APIs into a unified web interface. It provides IP, domain, URL, file, and hash analysis capabilities.

## Development Commands

```bash
# Run development server (starts on 0.0.0.0:5050)
python main.py

# Run with Docker Compose (Flask on 5050, Nginx on 80)
docker-compose up -d

# Production server
gunicorn --bind 0.0.0.0:5050 --timeout 120 main:app

# Run tests
python -m pytest app/tests/
```

## Architecture

**Layered Design:**
- **Routes Layer** (`app/routes/`): Blueprint-organized HTTP handlers. Each analysis type has its own route file.
- **Services Layer** (`app/services/`): Business logic and external API integrations. All third-party API calls happen here.
- **Utils Layer** (`app/utils/`): Cross-cutting concerns - LRU caching with TTL, sliding window rate limiting, rotating file logging.

**Application Factory:** `app/__init__.py` uses Flask's factory pattern with `create_app()`. Blueprints are registered here.

**Key Services:**
- `ip_service.py`: VPN detection (VPNapi), geolocation (IPinfo/MMDB), port scanning (Shodan), abuse reporting (AbuseIPDB), threat intel (OTX)
- `domain_service.py`: WHOIS, DNS records, SSL/TLS certificate analysis
- `url_service.py`: Security headers, redirect chains, technology detection (BuiltWith)
- `file_service.py` / `hash_service.py`: Malware analysis via Intezer

**Rate Limiting:** Built into service layer. AlienVault: 4 req/sec, others: 2 req/sec. Uses sliding window algorithm.

**Caching:** 30-minute TTL with thread-safe LRU cache (max 1000 items). Applied via `@timed_lru_cache` decorator.

## API Endpoints

| Route | Purpose |
|-------|---------|
| `POST /api/ip/check_ip` | Single IP analysis |
| `POST /api/ip/check_ips` | Batch IP analysis (CSV/XLSX/TXT) |
| `POST /api/domain/check_domain` | Domain info lookup |
| `POST /api/domain/analyze` | Full domain/URL analysis |
| `POST /api/file/analyze_file` | File malware analysis |
| `POST /api/hash/check_hash` | Hash reputation lookup |
| `POST /api/azure_error/search` | Azure AD error code lookup |
| `GET /api/health` | Health check |

## Environment Variables

Required API keys in `.env`:
- `VPNAPI_KEY`, `IPINFO_TOKEN`, `SHODAN_KEY`, `ABUSEIPDB_KEY` - IP analysis
- `ALIENVAULT` - OTX threat intelligence
- `INTEZER_KEY` - File/hash malware analysis
- `IP2WHOIS_KEY` - WHOIS lookups
- `MMDB_PATH` - Optional: Path to IPinfo MMDB for offline lookups

## Adding New Features

**New analysis service:**
1. Create service in `app/services/` with API logic
2. Create routes in `app/routes/` with blueprint
3. Register blueprint in `app/routes/__init__.py`
4. Create template in `templates/`

**New API integration:** Implement in service layer, wrap with `@timed_lru_cache`, add rate limiter if needed using `SlidingWindowRateLimiter` from `app/utils/rate_limiter.py`.

## Frontend

- Jinja2 templates in `templates/` (base.html is the layout)
- PWA-capable with service worker (`static/sw.js`)
- Mobile-optimized (see MOBILE_OPTIMIZATION.md)
- Embedded CyberChef v10.19.4 for data encoding/decoding
