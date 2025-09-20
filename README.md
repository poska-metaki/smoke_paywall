# Automated paywall testing

This tool probes a target article page for common content-exposure vectors (public JSON endpoints, client-side overlays, UA/referrer differences, blockable paywall scripts, and origin/API hints).  

**Important:** This repository is intended for authorized security testing only. Do **not** use findings against sites for which you do not have explicit written permission.

---

## Features

- Detects common paywall/content-exposure vectors:
  - Public JSON (strict detection: content type + parseability + article-related keys)
  - Inline hydration blobs (__NEXT_DATA__, __NUXT__, __APOLLO_STATE__, etc.)
  - Post-render XHR/fetch/GraphQL requests (metadata + top-level keys)
  - URL variants (print/amp/share/amp suffixes)
  - UA/Referer differences (desktop, iOS mobile, Googlebot, Google/Facebook/Twitter referers)
  - Client-side overlays (content present in the DOM)
  - "Paywall-like" JS, global metering variables, @media print stylesheets, Service Worker

- Produces a precise, machine-readable reports:
  - report.json — Structured summary of findings (id, title, severity, short description) + synthetic evidence (paths, snippets, metrics)
  - raw_probes.json — Raw probe data (tested requests, statuses, errors, timings).
  - js_scan.json — List of script URLs found in HTML (for asset/host reconnaissance).
  - xhr_scan.json — Observed XHR/Fetch/GraphQL requests (URL, status, content-type, snippet / detected top-level keys).
  - header_checks.json — Results of header-variation tests (UA / Referer) with rendering metrics (detected selector, text length).
  - screenshots/ — Series of captures: 01_baseline.png, 02_after_escape.png, 03_after_scroll.png, 04_after_css_hide.png (diagnostic).

---

## Requirements

- Node **18+** (script uses the global `fetch`)  
- Playwright

Install Playwright:

```bash
npm install playwright
npx playwright install
```

---

## Usage

```bash
node smoke-paywall.js --url "https://example.com/pages/article-handle"
```

options:

```bash
 --headful  --timeout 60000  --ua "MyUA/1.0"
```

## Legal & ethical

By using this tool you confirm you have explicit written permission to test the target(s). Unauthorized scanning or exploitation of systems you do not own may be illegal and unethical.

Make sure to keep a signed Rules of Engagement and follow responsible disclosure practices for any vulnerabilities you find.

## License

MIT