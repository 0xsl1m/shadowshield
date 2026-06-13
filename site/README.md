# ShadowShield landing page

A single, self-contained `index.html` (inline CSS/JS, fonts via Google Fonts CDN,
inline SVG shield + favicon — no build step, no external assets to host).

**Design:** "technical broadsheet / security whitepaper" — warm paper, ink, a single
burnt-vermilion accent, Fraunces + Spline Sans. The honest external benchmark is the
hero figure. Reveal animations are progressive enhancement (gated behind a `.js`
class), so all content is fully visible without JavaScript.

## Deploy

**Primary — Vercel → `https://shadowshield.xyz`** (domain bought via Vercel; DNS is
automatic). One-time setup in the Vercel dashboard:
1. **Add New… → Project → Import** the `0xsl1m/shadowshield` GitHub repo.
2. **Root Directory:** `site`  ·  **Framework Preset:** Other  ·  no build command.
3. **Deploy**, then **Settings → Domains → Add `shadowshield.xyz`** (and `www`).

Every push to `main` then auto-deploys (GitHub-integration auto-deploy only — no
`vercel` CLI). Security headers + clean URLs come from [`vercel.json`](vercel.json).

**Fallback — GitHub Pages** (`.github/workflows/pages.yml`) serves the same files at
`https://0xsl1m.github.io/shadowshield/`. `rel=canonical` points at shadowshield.xyz,
so the Vercel domain is authoritative for SEO. Disable the Pages workflow if you
want Vercel-only.

Preview locally: `python -m http.server -d site 8000` → http://127.0.0.1:8000
