#!/usr/bin/env python3
"""
NexusTrace — Cloudflare Administration CLI
==========================================

Manages Cloudflare-side configuration for cloud.nexustrace.net.

Usage:
    python3 scripts/cloudflare_admin.py <command> [args]

Commands:
    status                   Show zone overview (security level, plan, etc.)

    dns list                 List all DNS records for the zone
    dns sync                 Update the 'cloud' A record to the current public IP
                             (useful when your home/office IP changes)

    waf list                 List existing custom WAF firewall rules
    waf setup-api            Create a rule that skips Bot Fight Mode for requests
                             that include the X-API-Key header (required for the
                             enrichment API to work with programmatic clients)

    ratelimit list           List existing rate limit rules
    ratelimit setup          Create rate limits protecting /api/enrich/* and the
                             general site (safe defaults, adjustable)

    attack on                Enable "I'm Under Attack" mode
    attack off               Disable "I'm Under Attack" mode (return to previous level)

    security <level>         Set the zone security level:
                               essentially_off | low | medium | high | under_attack

    iplockdown show          Print iptables rules to restrict your origin server so
                             only Cloudflare IP ranges can reach ports 80 and 443.
                             Run these on your VM to hide the origin behind Cloudflare.

Required environment variables (add to .env):
    CF_API_TOKEN     Cloudflare API token with Zone:Read, DNS:Edit,
                     Firewall Rules:Edit, Zone Settings:Edit permissions
    CF_ZONE_ID       Zone ID for nexustrace.net (found in Cloudflare dashboard
                     → nexustrace.net → Overview → right sidebar)

Optional:
    CF_SUBDOMAIN     The proxied subdomain to manage (default: cloud)
"""

import os
import sys
import json
import argparse
import ipaddress
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("requests is not installed. Run: pip install requests")

# ---------------------------------------------------------------------------
# Load env
# ---------------------------------------------------------------------------

_env_path = Path(__file__).parent.parent / '.env'
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, _, v = line.partition('=')
            os.environ.setdefault(k.strip(), v.strip())


CF_API_TOKEN = os.getenv('CF_API_TOKEN', '')
CF_ZONE_ID   = os.getenv('CF_ZONE_ID', '')
CF_SUBDOMAIN = os.getenv('CF_SUBDOMAIN', 'cloud')

BASE_URL = 'https://api.cloudflare.com/client/v4'


# ---------------------------------------------------------------------------
# Cloudflare IP ranges (Cloudflare publishes these; periodically updated)
# Fetched live via the Cloudflare API when running iplockdown.
# Fallback static list included in case the API is unreachable.
# ---------------------------------------------------------------------------

CF_IPV4_FALLBACK = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
    '103.31.4.0/22',   '141.101.64.0/18', '108.162.192.0/18',
    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15',  '104.16.0.0/13',
    '104.24.0.0/14',   '172.64.0.0/13',   '131.0.72.0/22',
]
CF_IPV6_FALLBACK = [
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
    '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29',
    '2c0f:f248::/32',
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _headers():
    if not CF_API_TOKEN:
        sys.exit(
            "CF_API_TOKEN is not set.\n"
            "Add it to your .env file:\n"
            "  CF_API_TOKEN=your-token-here\n\n"
            "Create a token at: https://dash.cloudflare.com/profile/api-tokens\n"
            "Required permissions: Zone:Read, DNS:Edit, Firewall Rules:Edit, "
            "Zone Settings:Edit"
        )
    return {
        'Authorization': f'Bearer {CF_API_TOKEN}',
        'Content-Type': 'application/json',
    }


def _require_zone():
    if not CF_ZONE_ID:
        sys.exit(
            "CF_ZONE_ID is not set.\n"
            "Add it to your .env file:\n"
            "  CF_ZONE_ID=your-zone-id\n\n"
            "Find it in the Cloudflare dashboard:\n"
            "  nexustrace.net → Overview → right sidebar → Zone ID"
        )
    return CF_ZONE_ID


def _get(path, params=None):
    r = requests.get(f'{BASE_URL}{path}', headers=_headers(), params=params, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get('success'):
        errors = data.get('errors', [])
        sys.exit(f"Cloudflare API error: {errors}")
    return data


def _post(path, payload, _allow_codes=None):
    r = requests.post(f'{BASE_URL}{path}', headers=_headers(), json=payload, timeout=15)
    if _allow_codes and r.status_code in _allow_codes:
        return r.json()
    r.raise_for_status()
    data = r.json()
    if not data.get('success'):
        errors = data.get('errors', [])
        sys.exit(f"Cloudflare API error: {errors}")
    return data


def _patch(path, payload):
    r = requests.patch(f'{BASE_URL}{path}', headers=_headers(), json=payload, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get('success'):
        errors = data.get('errors', [])
        sys.exit(f"Cloudflare API error: {errors}")
    return data


def _put(path, payload):
    r = requests.put(f'{BASE_URL}{path}', headers=_headers(), json=payload, timeout=15)
    r.raise_for_status()
    data = r.json()
    if not data.get('success'):
        errors = data.get('errors', [])
        sys.exit(f"Cloudflare API error: {errors}")
    return data


def _get_public_ip():
    """Detect the current public IP of this machine."""
    for url in ['https://api4.my-ip.io/ip', 'https://ifconfig.me/ip', 'https://icanhazip.com']:
        try:
            r = requests.get(url, timeout=5)
            ip = r.text.strip()
            ipaddress.IPv4Address(ip)  # validate
            return ip
        except Exception:
            continue
    sys.exit("Could not determine public IP address.")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status():
    zone_id = _require_zone()
    zone = _get(f'/zones/{zone_id}')['result']
    settings = _get(f'/zones/{zone_id}/settings')['result']
    settings_map = {s['id']: s['value'] for s in settings}

    print(f"\n{'='*50}")
    print(f"  Zone: {zone['name']}")
    print(f"{'='*50}")
    print(f"  Zone ID:         {zone['id']}")
    print(f"  Plan:            {zone['plan']['name']}")
    print(f"  Status:          {zone['status']}")
    print(f"  Nameservers:     {', '.join(zone.get('name_servers', []))}")
    print(f"\n  Security Level:  {settings_map.get('security_level', 'unknown')}")
    print(f"  SSL Mode:        {settings_map.get('ssl', 'unknown')}")
    print(f"  Always HTTPS:    {settings_map.get('always_use_https', 'unknown')}")
    print(f"  Min TLS:         {settings_map.get('min_tls_version', 'unknown')}")
    print(f"  HSTS:            {settings_map.get('security_header', {}).get('strict_transport_security', {}).get('enabled', False)}")
    print(f"  Bot Fight Mode:  {settings_map.get('bot_fight_mode', 'unknown')}")
    print(f"  Browser Check:   {settings_map.get('browser_check', 'unknown')}")
    print(f"  Challenge TTL:   {settings_map.get('challenge_ttl', 'unknown')}s")
    print()


def cmd_dns_list():
    zone_id = _require_zone()
    records = _get(f'/zones/{zone_id}/dns_records', params={'per_page': 100})['result']
    print(f"\n{'TYPE':<8}  {'NAME':<35}  {'CONTENT':<45}  {'PROXIED':<8}  TTL")
    print('-' * 110)
    for r in records:
        print(
            f"{r['type']:<8}  {r['name']:<35}  {r['content']:<45}  "
            f"{'yes' if r.get('proxied') else 'no':<8}  {r['ttl']}"
        )
    print()


def cmd_dns_sync():
    """Update the cloud A record to the current public IP."""
    zone_id = _require_zone()
    subdomain = CF_SUBDOMAIN
    public_ip = _get_public_ip()
    print(f"Current public IP: {public_ip}")

    # Find the record
    records = _get(f'/zones/{zone_id}/dns_records', params={'type': 'A', 'name': f'{subdomain}.nexustrace.net'})['result']

    if not records:
        # Create it
        print(f"No A record found for {subdomain}.nexustrace.net — creating it...")
        result = _post(f'/zones/{zone_id}/dns_records', {
            'type': 'A',
            'name': subdomain,
            'content': public_ip,
            'ttl': 1,           # 1 = auto (Cloudflare managed)
            'proxied': True,    # Orange cloud on — traffic via Cloudflare
        })['result']
        print(f"Created: {result['name']} → {result['content']} (proxied={result['proxied']})")
    else:
        record = records[0]
        if record['content'] == public_ip:
            print(f"A record is already up to date: {record['name']} → {public_ip}")
            return
        old_ip = record['content']
        result = _patch(f'/zones/{zone_id}/dns_records/{record["id"]}', {
            'type': 'A',
            'name': subdomain,
            'content': public_ip,
            'ttl': 1,
            'proxied': True,
        })['result']
        print(f"Updated: {result['name']} → {old_ip}  =>  {result['content']}")
    print()


def cmd_waf_list():
    zone_id = _require_zone()
    rules = _get(f'/zones/{zone_id}/firewall/rules', params={'per_page': 100})['result']
    if not rules:
        print("No custom WAF firewall rules found.")
        return
    print(f"\n{'ID':<20}  {'DESCRIPTION':<40}  ACTION")
    print('-' * 75)
    for r in rules:
        print(f"{r['id']:<20}  {r.get('description', ''):<40}  {r['action']}")
    print()


def cmd_waf_setup_api():
    """
    Create a Cloudflare Firewall Rule that bypasses Bot Fight Mode / Browser
    Integrity Check for requests that include the X-API-Key header.

    Without this rule, automated API clients (curl, Python scripts, SIEM
    connectors) may receive a Cloudflare challenge page instead of a response.
    """
    zone_id = _require_zone()
    description = "NexusTrace: Allow enrichment API clients (X-API-Key header)"

    # Check if a rule with this description already exists
    existing = _get(f'/zones/{zone_id}/firewall/rules', params={'per_page': 100})['result']
    for r in existing:
        if r.get('description') == description:
            print(f"Rule already exists (id={r['id']}): {description}")
            return

    # First create the filter expression
    filter_expr = 'any(http.request.headers["x-api-key"][*] ne "")'
    filter_resp = _post(f'/zones/{zone_id}/filters', [{
        'expression': filter_expr,
        'description': description,
    }])
    filter_id = filter_resp['result'][0]['id']
    print(f"Created filter: {filter_id}")

    # Then create the firewall rule using that filter
    rule_resp = _post(f'/zones/{zone_id}/firewall/rules', [{
        'filter': {'id': filter_id},
        'action': 'allow',
        'description': description,
        'priority': 1,
    }])
    rule = rule_resp['result'][0]
    print(f"Created WAF rule: {rule['id']}")
    print(f"  Action: {rule['action']}")
    print(f"  Expression: {filter_expr}")
    print(f"  Description: {rule.get('description')}")
    print(
        "\nAPI clients that send X-API-Key will now bypass Bot Fight Mode and "
        "Browser Integrity Check.\n"
    )


def cmd_ratelimit_list():
    zone_id = _require_zone()
    rules = _get(f'/zones/{zone_id}/rate_limits', params={'per_page': 100})['result']
    if not rules:
        print("No rate limit rules found.")
        return
    print(f"\n{'ID':<25}  {'URL':<45}  THRESHOLD  PERIOD")
    print('-' * 95)
    for r in rules:
        url = r.get('match', {}).get('request', {}).get('url', '')
        threshold = r.get('threshold', '')
        period    = r.get('period', '')
        print(f"{r['id']:<25}  {url:<45}  {threshold:<10} {period}s")
    print()


def cmd_ratelimit_setup():
    """
    Create two rate limiting rules:

      1. Enrichment API (/api/enrich/*) — 60 requests per minute per IP.
         Appropriate for SIEM connectors doing batch enrichment.

      2. General site (/*) — 300 requests per minute per IP.
         Protects against scraping / DDoS of the web UI.

    These limits are conservative starting points. Adjust the threshold
    values in the script to match your actual usage patterns.
    """
    zone_id = _require_zone()

    rules_to_create = [
        {
            'description': 'NexusTrace: Enrichment API rate limit',
            'match': {
                'request': {
                    'url': '*.nexustrace.net/api/enrich/*',
                    'schemes': ['HTTP', 'HTTPS'],
                    'methods': ['POST'],
                }
            },
            'threshold': 60,    # requests
            'period': 60,       # seconds
            'action': {
                'mode': 'simulate',  # Change to 'ban' once you've validated the threshold
                'timeout': 3600,    # Ban duration (must be > period); 1 hour
                'response': {
                    'content_type': 'application/json',
                    'body': '{"error": "Rate limit exceeded. Try again in 60 seconds."}',
                },
            },
            'disabled': False,
        },
        {
            'description': 'NexusTrace: General site rate limit',
            'match': {
                'request': {
                    'url': '*.nexustrace.net/*',
                    'schemes': ['HTTP', 'HTTPS'],
                    'methods': ['GET', 'POST'],
                }
            },
            'threshold': 300,
            'period': 60,
            'action': {
                'mode': 'simulate',  # Change to 'ban' once validated
                'timeout': 3600,    # Ban duration (must be > period); 1 hour
                'response': {
                    'content_type': 'text/plain',
                    'body': 'Too many requests.',
                },
            },
            'disabled': False,
        },
    ]

    existing_resp = _get(f'/zones/{zone_id}/rate_limits', params={'per_page': 100})
    existing_descriptions = {r.get('description') for r in (existing_resp.get('result') or [])}

    for rule in rules_to_create:
        if rule['description'] in existing_descriptions:
            print(f"Already exists, skipping: {rule['description']}")
            continue
        resp = _post(f'/zones/{zone_id}/rate_limits', rule, _allow_codes={400})
        if not resp.get('success'):
            codes = [e.get('code') for e in resp.get('errors', [])]
            if 10021 in codes:
                print(
                    "Rate limiting is not available on the Cloudflare Free plan.\n"
                    "Upgrade to Pro at https://dash.cloudflare.com/ to enable configurable rate limits.\n"
                    "Cloudflare's automatic DDoS protection is still active on all plans."
                )
                return
            sys.exit(f"Cloudflare API error: {resp.get('errors')}")
        result = resp['result']
        print(f"Created rate limit: {result['id']}")
        print(f"  Description: {result.get('description')}")
        print(f"  URL: {result['match']['request']['url']}")
        print(f"  Threshold: {result['threshold']} req / {result['period']}s")
        print(f"  Mode: {result['action']['mode']}  (change to 'ban' when ready)\n")


def cmd_attack(state):
    zone_id = _require_zone()
    level = 'under_attack' if state == 'on' else 'high'
    result = _patch(f'/zones/{zone_id}/settings/security_level', {'value': level})['result']
    print(f"Security level set to: {result['value']}")
    if state == 'on':
        print("Under Attack mode is now ACTIVE. All visitors will see a 5-second challenge.")
    else:
        print("Under Attack mode disabled. Security level returned to 'high'.")
    print()


def cmd_security(level):
    valid = {'essentially_off', 'low', 'medium', 'high', 'under_attack'}
    if level not in valid:
        sys.exit(f"Invalid security level '{level}'. Choose from: {', '.join(sorted(valid))}")
    zone_id = _require_zone()
    result = _patch(f'/zones/{zone_id}/settings/security_level', {'value': level})['result']
    print(f"Security level set to: {result['value']}")
    print()


def cmd_iplockdown():
    """
    Print iptables + ip6tables rules to restrict the origin VM so only
    Cloudflare's IP ranges can reach ports 80 and 443.

    This hides your real IP — even if someone discovers your home IP, they
    cannot reach NexusTrace directly; all traffic must go through Cloudflare.

    Run the printed commands on your VM (requires root/sudo).
    """
    # Try to fetch live IP ranges from Cloudflare
    ipv4_ranges = CF_IPV4_FALLBACK[:]
    ipv6_ranges = CF_IPV6_FALLBACK[:]
    try:
        r = requests.get('https://api.cloudflare.com/client/v4/ips', timeout=10)
        data = r.json()
        if data.get('success'):
            ipv4_ranges = data['result'].get('ipv4_cidrs', ipv4_ranges)
            ipv6_ranges = data['result'].get('ipv6_cidrs', ipv6_ranges)
            print("# IP ranges fetched live from Cloudflare API")
        else:
            print("# Using bundled IP ranges (Cloudflare API unavailable)")
    except Exception:
        print("# Using bundled IP ranges (Cloudflare API unreachable)")

    print("""
# ============================================================
# NexusTrace — Origin lockdown via iptables
# Run these commands on your VM as root (or with sudo).
#
# What this does:
#   - Allows traffic on ports 80/443 ONLY from Cloudflare IPs
#   - Drops all other connections to those ports
#   - Leaves SSH (port 22) and other ports untouched
#
# IMPORTANT: Run the SSH rule first to avoid locking yourself out.
# ============================================================

# Flush existing HTTP/HTTPS INPUT rules (optional — review first)
# sudo iptables -F INPUT
# sudo ip6tables -F INPUT

# Always allow loopback and established connections
sudo iptables  -A INPUT -i lo -j ACCEPT
sudo iptables  -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo ip6tables -A INPUT -i lo -j ACCEPT
sudo ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (adjust port if you use a non-standard one)
sudo iptables  -A INPUT -p tcp --dport 22 -j ACCEPT
sudo ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
""")

    print("# Allow Cloudflare IPv4 ranges on ports 80 and 443")
    for cidr in ipv4_ranges:
        print(f"sudo iptables -A INPUT -p tcp -s {cidr} --dport 80  -j ACCEPT")
        print(f"sudo iptables -A INPUT -p tcp -s {cidr} --dport 443 -j ACCEPT")

    print()
    print("# Allow Cloudflare IPv6 ranges on ports 80 and 443")
    for cidr in ipv6_ranges:
        print(f"sudo ip6tables -A INPUT -p tcp -s {cidr} --dport 80  -j ACCEPT")
        print(f"sudo ip6tables -A INPUT -p tcp -s {cidr} --dport 443 -j ACCEPT")

    print("""
# Drop everything else on ports 80 and 443
sudo iptables  -A INPUT -p tcp --dport 80  -j DROP
sudo iptables  -A INPUT -p tcp --dport 443 -j DROP
sudo ip6tables -A INPUT -p tcp --dport 80  -j DROP
sudo ip6tables -A INPUT -p tcp --dport 443 -j DROP

# Persist rules across reboots (Debian/Ubuntu)
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save

# Persist rules across reboots (RHEL/CentOS/Fedora)
# sudo service iptables save

# ============================================================
# To verify rules are in place:
#   sudo iptables  -L INPUT -v --line-numbers
#   sudo ip6tables -L INPUT -v --line-numbers
#
# To remove all rules and start over:
#   sudo iptables  -F INPUT
#   sudo ip6tables -F INPUT
# ============================================================
""")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='NexusTrace Cloudflare Administration CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest='command', metavar='command')

    sub.add_parser('status', help='Zone overview')

    dns_p = sub.add_parser('dns', help='DNS record management')
    dns_p.add_argument('action', choices=['list', 'sync'])

    waf_p = sub.add_parser('waf', help='WAF / firewall rule management')
    waf_p.add_argument('action', choices=['list', 'setup-api'])

    rl_p = sub.add_parser('ratelimit', help='Rate limit management')
    rl_p.add_argument('action', choices=['list', 'setup'])

    atk_p = sub.add_parser('attack', help='Toggle Under Attack mode')
    atk_p.add_argument('state', choices=['on', 'off'])

    sec_p = sub.add_parser('security', help='Set security level')
    sec_p.add_argument('level', choices=['essentially_off', 'low', 'medium', 'high', 'under_attack'])

    sub.add_parser('iplockdown', help='Print iptables rules to allow only Cloudflare IPs')

    args = parser.parse_args()

    if args.command == 'status':
        cmd_status()
    elif args.command == 'dns':
        if args.action == 'list':
            cmd_dns_list()
        elif args.action == 'sync':
            cmd_dns_sync()
    elif args.command == 'waf':
        if args.action == 'list':
            cmd_waf_list()
        elif args.action == 'setup-api':
            cmd_waf_setup_api()
    elif args.command == 'ratelimit':
        if args.action == 'list':
            cmd_ratelimit_list()
        elif args.action == 'setup':
            cmd_ratelimit_setup()
    elif args.command == 'attack':
        cmd_attack(args.state)
    elif args.command == 'security':
        cmd_security(args.level)
    elif args.command == 'iplockdown':
        cmd_iplockdown()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
