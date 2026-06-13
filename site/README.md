# ShadowShield landing page

A single, self-contained `index.html` (inline CSS/JS, fonts via Google Fonts CDN,
inline SVG shield + favicon — no build step, no external assets to host).

**Design:** "technical broadsheet / security whitepaper" — warm paper, ink, a single
burnt-vermilion accent, Fraunces + Spline Sans. The honest external benchmark is the
hero figure. Reveal animations are progressive enhancement (gated behind a `.js`
class), so all content is fully visible without JavaScript.

## Deploy

Published to GitHub Pages by `.github/workflows/pages.yml` on push to `main`.
One-time setup: **Settings → Pages → Source = GitHub Actions**. Live at
`https://0xsl1m.github.io/shadowshield/`.

Preview locally: `python -m http.server -d site 8000` → http://127.0.0.1:8000
