# Cloudflare Security Setup

## 1) Deploy the secure Worker
1. Install Wrangler on your machine.
2. Login:
```bash
wrangler login
```
3. Create `.dev.vars` from `.dev.vars.example` and fill real secrets.
4. Deploy:
```bash
wrangler deploy
```

## 2) Route APIs to Worker (same domain)
In `wrangler.toml`, uncomment `routes` and set your real domain:
```toml
routes = [
  { pattern = "your-domain.com/api/lead", zone_name = "your-domain.com" }
]
```
Then deploy again:
```bash
wrangler deploy
```

## 3) Enable Cloudflare anti-DDoS protections
From Cloudflare Dashboard (domain zone):
1. `Security -> WAF -> Managed rules`: enable all core managed rules.
2. `Security -> Bots`: enable `Bot Fight Mode` (or Super Bot Fight if available).
3. `Security -> Settings`: set security level to at least `Medium`.
4. `Security -> DDoS`: keep L3/L4 and HTTP DDoS protection enabled.
5. `Security -> WAF -> Rate limiting rules`:
   - Rule A: protect `/api/lead` (for example 20 requests / 1 minute / IP).
   - Action: `Managed Challenge` or `Block`.
   - Rule B: stricter for suspicious countries/IPs if needed.
6. During active attack only, enable `Under Attack Mode`.

## 4) Turnstile keys
1. Keep `TURNSTILE_SECRET` only in Worker secrets.
2. Put your real site key in `index.html` (`TURNSTILE_SITE_KEY`).

## 5) Validation checklist
1. Submitting form without Turnstile should fail.
2. Submitting too many requests quickly from same IP should return `429`.
3. Large payloads should return `413`.
4. Non-JSON submissions should return `415`.
