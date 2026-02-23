# Cloudflare Administration

NexusTrace ships a CLI script — `scripts/cloudflare_admin.py` — that automates common Cloudflare tasks for the `cloud.nexustrace.net` deployment. This document covers the one-time setup, every available command, and recommended hardening steps for a locally-hosted VM behind Cloudflare.

---

## 1. One-Time Setup

### 1a. Create a Cloudflare API Token

You need a **scoped** API token, not your Global API Key.

1. Go to [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token** → **Create Custom Token**
3. Set these permissions:

   | Resource          | Scope           | Permission |
   |-------------------|-----------------|------------|
   | Zone              | nexustrace.net  | Read       |
   | Zone › DNS        | nexustrace.net  | Edit       |
   | Zone › Firewall Rules | nexustrace.net | Edit   |
   | Zone › Zone Settings | nexustrace.net | Edit   |

4. Set **Zone Resources** → **Include** → **Specific zone** → `nexustrace.net`
5. Click **Continue to Summary** → **Create Token**
6. Copy the token — it is only shown once

### 1b. Find your Zone ID

1. Go to the Cloudflare dashboard → click `nexustrace.net`
2. On the **Overview** page, scroll down the right sidebar
3. Copy the **Zone ID** (a 32-character hex string)

### 1c. Add credentials to `.env`

```
CF_API_TOKEN=your-api-token-here
CF_ZONE_ID=your-zone-id-here
CF_SUBDOMAIN=cloud
```

`CF_SUBDOMAIN` is the label of the A record managed by the `dns sync` command — leave it as `cloud` for `cloud.nexustrace.net`.

---

## 2. Commands

All commands are run from the NexusTrace project root:

```bash
python3 scripts/cloudflare_admin.py <command> [args]
```

---

### `status` — Zone overview

Shows the current state of the zone: plan, security level, SSL mode, Bot Fight Mode, HSTS, and more.

```bash
python3 scripts/cloudflare_admin.py status
```

Example output:
```
==================================================
  Zone: nexustrace.net
==================================================
  Zone ID:         abc123...
  Plan:            Free
  Status:          active
  Nameservers:     grace.ns.cloudflare.com, ...

  Security Level:  medium
  SSL Mode:        full
  Always HTTPS:    on
  Min TLS:         1.2
  HSTS:            True
  Bot Fight Mode:  on
  Browser Check:   on
  Challenge TTL:   1800s
```

---

### `dns list` — List DNS records

```bash
python3 scripts/cloudflare_admin.py dns list
```

Shows all A, AAAA, CNAME, MX, TXT, and other records for `nexustrace.net`.

---

### `dns sync` — Update the A record to your current public IP

Your home/office IP may change when your ISP re-assigns it. This command detects the current public IP of the machine running the script and updates the `cloud.nexustrace.net` A record in Cloudflare automatically.

```bash
python3 scripts/cloudflare_admin.py dns sync
```

Example output:
```
Current public IP: 203.0.113.42
Updated: cloud.nexustrace.net → 203.0.113.10  =>  203.0.113.42
```

**Automating DNS sync with cron**

To keep the DNS record updated automatically, add a cron job on your VM:

```bash
crontab -e
```

Add this line to check every 15 minutes:

```
*/15 * * * * cd /path/to/NexusTrace && python3 scripts/cloudflare_admin.py dns sync >> logs/dns_sync.log 2>&1
```

---

### `waf list` — List custom WAF rules

```bash
python3 scripts/cloudflare_admin.py waf list
```

---

### `waf setup-api` — Allow API clients through Bot Fight Mode

Cloudflare's Bot Fight Mode and Browser Integrity Check block automated clients (curl, Python scripts, SIEM connectors) with a `403` challenge page before they ever reach NexusTrace. This command creates a WAF firewall rule that **allows** any request carrying an `X-API-Key` header, bypassing those checks.

```bash
python3 scripts/cloudflare_admin.py waf setup-api
```

Example output:
```
Created filter: f1abc...
Created WAF rule: r2def...
  Action: allow
  Expression: http.request.headers["x-api-key"] ne ""
  Description: NexusTrace: Allow enrichment API clients (X-API-Key header)

API clients that send X-API-Key will now bypass Bot Fight Mode and Browser Integrity Check.
```

**Run this once.** The command is idempotent — running it again detects the existing rule and skips creation.

> **Note:** This rule does not open any security hole. Only clients that also have a valid `X-API-Key` (checked by NexusTrace itself) can use the enrichment API. The WAF rule only prevents Cloudflare from blocking them before they reach the origin.

---

### `ratelimit list` — List rate limit rules

```bash
python3 scripts/cloudflare_admin.py ratelimit list
```

---

### `ratelimit setup` — Create sensible rate limits

Creates two rate limiting rules:

| Rule | URL pattern | Threshold | Action |
|------|-------------|-----------|--------|
| Enrichment API | `/api/enrich/*` | 60 req/min/IP | simulate |
| General site | `/*` | 300 req/min/IP | simulate |

```bash
python3 scripts/cloudflare_admin.py ratelimit setup
```

Rules are created in **simulate** mode first — they log matched requests but do not block anything. Once you have confirmed the thresholds are appropriate (no false positives in Cloudflare's analytics), change `'mode': 'simulate'` to `'mode': 'ban'` in the script and re-run, or edit the rules directly in the Cloudflare dashboard.

> **Note:** Rate limiting requires Cloudflare's **Pro plan or higher**. On the Free plan this command will return a permissions error — the rules simply won't be created.

---

### `attack on` / `attack off` — Toggle Under Attack mode

Enables or disables Cloudflare's "I'm Under Attack" mode. When on, every visitor sees a 5-second JavaScript challenge before reaching the site.

```bash
# Enable — use when the site is actively being attacked
python3 scripts/cloudflare_admin.py attack on

# Disable — return to 'high' security level
python3 scripts/cloudflare_admin.py attack off
```

---

### `security <level>` — Set the zone security level

```bash
python3 scripts/cloudflare_admin.py security medium
```

Available levels:

| Level | What it does |
|-------|-------------|
| `essentially_off` | No challenges issued (not recommended) |
| `low` | Challenges only the most suspicious traffic |
| `medium` | Default — challenges moderately suspicious traffic |
| `high` | Challenges all visitors with elevated threat scores |
| `under_attack` | 5-second JS challenge for everyone |

---

### `iplockdown show` — Lock the origin to Cloudflare only

Prints ready-to-run `iptables` and `ip6tables` commands that restrict your VM so that **only Cloudflare's IP ranges** can reach ports 80 and 443. This is one of the most effective things you can do to protect a locally-hosted server: even if someone discovers your home IP, they cannot reach NexusTrace directly.

```bash
python3 scripts/cloudflare_admin.py iplockdown
```

The output is a full shell script you can copy and paste into your VM:

```bash
# Paste and run on the VM (requires sudo)
python3 scripts/cloudflare_admin.py iplockdown | bash
```

> **Before running:** make sure port 22 (SSH) is allowed. The generated rules always include an SSH allow rule, but double-check if you use a non-standard SSH port. Edit the `--dport 22` line in the output before running.

**Persisting across reboots**

The script includes the commands to install and enable `iptables-persistent` (Debian/Ubuntu) or `service iptables save` (RHEL/CentOS). The Cloudflare IP ranges are fetched live from the Cloudflare API each time you run `iplockdown`, so if Cloudflare adds new ranges you just re-run the command.

---

## 3. Recommended Hardening Sequence

For a fresh deployment, run these in order:

```bash
# 1. Verify the zone looks correct
python3 scripts/cloudflare_admin.py status

# 2. Sync the A record to your current IP
python3 scripts/cloudflare_admin.py dns sync

# 3. Allow enrichment API clients through Bot Fight Mode
python3 scripts/cloudflare_admin.py waf setup-api

# 4. Create rate limits (Pro plan only; skippable on Free)
python3 scripts/cloudflare_admin.py ratelimit setup

# 5. Lock the origin — only Cloudflare can reach ports 80/443
#    Review the output, then pipe to bash when satisfied
python3 scripts/cloudflare_admin.py iplockdown
# → review output, then: python3 scripts/cloudflare_admin.py iplockdown | bash
```

---

## 4. Cloudflare Dashboard Settings (Manual)

A few settings are not yet automated in the script. Configure these manually in the Cloudflare dashboard (`nexustrace.net` → relevant section):

| Setting | Recommended value | Where |
|---------|------------------|-------|
| SSL/TLS mode | **Full (strict)** | SSL/TLS → Overview |
| Always Use HTTPS | **On** | SSL/TLS → Edge Certificates |
| Minimum TLS Version | **TLS 1.2** | SSL/TLS → Edge Certificates |
| HSTS | **Enable** (max-age 6 months, include subdomains) | SSL/TLS → Edge Certificates |
| Automatic HTTPS Rewrites | **On** | SSL/TLS → Edge Certificates |
| Brotli | **On** | Speed → Optimization |
| Rocket Loader | **Off** — can interfere with NexusTrace JS | Speed → Optimization |

**SSL mode: Full (strict)** requires a valid certificate on the origin server. With the Docker setup, Nginx handles HTTP internally, so Cloudflare terminates TLS at the edge and proxies plain HTTP to your VM on port 80. For Full (strict), you'd need a cert on Nginx too — a free Cloudflare Origin Certificate works well for this.

---

## 5. Cloudflare Tunnel (Optional — More Secure)

Instead of port-forwarding on your router, you can use **Cloudflare Tunnel** (`cloudflared`). The tunnel creates an outbound-only encrypted connection from your VM to Cloudflare — no inbound ports need to be open at all, and your public IP is never used.

```bash
# Install cloudflared on the VM
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb

# Authenticate
cloudflared tunnel login

# Create a tunnel
cloudflared tunnel create nexustrace

# Configure routing (creates config.yml)
cloudflared tunnel route dns nexustrace cloud.nexustrace.net

# Run the tunnel (points to local NexusTrace)
cloudflared tunnel --url http://localhost:5050 run nexustrace

# Or run as a systemd service
sudo cloudflared service install
sudo systemctl start cloudflared
```

With a tunnel active, the `cloud.nexustrace.net` DNS record is managed by Cloudflare automatically as a `CNAME` to a `*.cfargotunnel.com` address — the `dns sync` command is not needed.
