# Oplogica homepage (static site source)

Source for the public marketing homepage at <https://oplogica.com/>.

This is a plain, dependency-free static site (one self-contained HTML file per
page, embedded CSS, no build step, no tracking, no external fonts). It is
entirely separate from the OVA evidence-integrity demo and verifier:

- `index.html` — homepage (hero, proof cards, architecture flow, capabilities,
  scope, design-partner pilot, footer).
- `pilot.html` — focused design-partner pilot brief.
- `assets/` — Oplogica brand assets (hero banner, icon, horizontal logo,
  wordmark). Mirrors the brand PNGs tracked at the repository root.

## Deployment

The live homepage is served by a small Express static server
(`/var/www/oplogica-com/server.js`) from `/var/www/oplogica-com/public/`, fronted
by Nginx. `/ova-demo/*` is proxied to the OVA FastAPI service and is **not**
part of this site.

To deploy, copy the files in this folder into the server's `public/` directory:

```
public/index.html
public/pilot.html
public/assets/*
```

No service restart is required — Express serves files from disk on each request.

## Scope note

Oplogica verifies evidence integrity and binding. It does not certify
correctness, fairness, or legal compliance.
