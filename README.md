# Automated paywall testing

This tool probes a target article page for common content-exposure vectors (public JSON endpoints, client-side overlays, UA/referrer differences, blockable paywall scripts, and origin/API hints).  

**Important:** This repository is intended for authorized security testing only. Do **not** use findings against sites for which you do not have explicit written permission.

<img width="2076" height="1112" alt="console" src="https://github.com/user-attachments/assets/b0b2119b-32c6-417c-a6cf-886ab7faedca" />

---

## Features

- Detects common paywall / content-exposure vectors (metadata-only):
    - Public JSON endpoints (strict: content-type + JSON parseability + article-related keys)
	- Inline hydration blobs (__NEXT_DATA__, __NUXT__, __APOLLO_STATE__, etc.)
	- Post-render XHR / fetch / GraphQL (URL, method, status, content-type, size, top-level keys)
	- URL variants (print / amp / share / amp-suffix)
	- UA / Referer differences (desktop, iOS mobile, Googlebot, Google/Facebook/Twitter referers)
	- Client-side overlays (article node present in the DOM)
	- Signals: “paywall-like” JS filenames, global metering variables, @media print stylesheets, Service Worker, JSON-LD Article markers
	- Early hooks & CDP: document_start fetch/XHR instrumentation + CDP Network events (metadata only)
- Produces precise, machine-readable reports and a concise console summary
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
node smoke-paywall.js --url "https://site/article" [--headful] [--timeout 60000] [--ua "UA String"]
```

## Legal & ethical

By using this tool you confirm you have explicit written permission to test the target(s). Unauthorized scanning or exploitation of systems you do not own may be illegal and unethical.

Make sure to keep a signed Rules of Engagement and follow responsible disclosure practices for any vulnerabilities you find.

## License

MIT
