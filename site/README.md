# ShadowShield site

The site is a Next.js App Router static export using React and TypeScript. The hero combines a local WebP illustration with an original lightweight WebGL atmosphere and CSS orbits; the full still composition remains visible without WebGL or JavaScript. All continuous motion respects reduced motion and the page-wide pause control. The WebGL loop also pauses when the hero is offscreen or the page is hidden.

From `site/`, run `npm ci`, then `npm run dev` for local development or `npm run build` for the deployable `out/` directory. The build copies the authoritative OG, robots, sitemap and llms files into `public/` and verifies the exported CSP hashes.

The primary site is Vercel with root directory `site`. `vercel.json` specifies `npm run build` and `out` as the output directory, preserves the security headers and redirects `www` to the apex. Deployment remains governed separately from local development. The GitHub Pages workflow builds a separate export with `NEXT_PUBLIC_BASE_PATH=/shadowshield` and uploads `site/out`; GitHub Pages controls its own HTTP headers and does not apply Vercel's header configuration.

Next's static export emits bootstrap scripts whose contents can vary across operating systems. The export step externalizes only recognized Next/Turbopack bootstrap shapes into same-origin, content-addressed files, preserving their order and attributes; unexpected inline scripts fail the build. Static JSON-LD and the exact style block in `og.html` remain hash-authorized. The CSP does not allow `unsafe-inline` or `unsafe-eval`. After changing the static JSON-LD or OG style, run `npm run build:update-csp`, review the `vercel.json` hash changes and then run `npm run build`. Production build fails if the remaining inline hashes drift or exported HTML introduces style/event attributes. The site-build workflow checks this on pull requests.

The benchmark figures are dataset- and configuration-specific, and the inspection example is illustrative. Preserve those qualifications when editing copy. `pytest tests/test_site_security.py` checks version metadata, headers and the checked-export contract.
