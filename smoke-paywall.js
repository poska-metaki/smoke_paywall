#!/usr/bin/env node
/**
 * smoke-paywall.js
 *
 * Usage:
 *   node smoke-paywall.js --url "https://site/article" [--headful] [--timeout 60000] [--ua "UA String"]
 *
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

/* ------------------------------- CLI ----------------------------------- */

function parseCLI() {
  const args = process.argv.slice(2);
  const getArg = (flag) => {
    const i = args.indexOf(flag);
    return (i !== -1 && args[i + 1] && !args[i + 1].startsWith('--')) ? args[i + 1] : null;
  };
  const url = getArg('--url') || process.env.TEST_URL || null;
  const headful = args.includes('--headful');
  const timeout = parseInt(getArg('--timeout') || '', 10);
  const userAgent = getArg('--ua') || null;
  return { url, headful, timeout: Number.isFinite(timeout) ? timeout : 45000, userAgent };
}
const { url: TEST_URL, headful: HEADFUL, timeout: NAV_TIMEOUT, userAgent: UA_OVERRIDE } = parseCLI();
if (!TEST_URL) {
  console.error('ERROR: provide --url or TEST_URL env var');
  process.exit(2);
}

/* ----------------------------- Utils ----------------------------------- */

function tsNow() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function safeName(u) { return u.replace(/[^a-z0-9._-]+/gi, '_').slice(0, 160); }
function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }
async function writeJson(fp, obj) { await fs.promises.writeFile(fp, JSON.stringify(obj, null, 2), 'utf8'); }
function short(s, n = 300) { return (s || '').slice(0, n); }

const OUT_ROOT = `./smoke_paywall_${tsNow()}`;
ensureDir(OUT_ROOT);

/* -------------------------- Heuristics --------------------------------- */

const SELECTORS = ['main', 'article', '.post-content', '.entry-content', '.page-content'];
const OVERLAYS = [
  '.fr-gate-overlay', '.fr-gate-container',
  '#CartDrawer-Overlay', 'cart-drawer',
  '#CybotCookiebotDialog', '.issue-article-cover'
];

function isJsonCT(r) {
  const ct = (r.headers?.['content-type'] || '').toLowerCase();
  return ct.includes('application/json') || ct.includes('+json');
}
function hasArticleFieldsObj(obj) {
  if (!obj || typeof obj !== 'object') return false;
  const s = JSON.stringify(obj).toLowerCase();
  return /\b(body_html|articlebody|"body":|"rendered":|"renderedbody"|content_html|contenthtml|content\.blocks)\b/.test(s);
}
function hasArticleFieldsText(txt) {
  if (!txt) return false;
  return /"body_html"|"articleBody"|"renderedBody"|"content_html"|"contentHtml"|"<article"|"<main"/i.test(txt);
}

/* ----------------------------- Fetch helper ---------------------------- */

async function fetchText(url, opts = {}) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), opts.timeout || 20000);
    const r = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': UA_OVERRIDE || 'smoke-paywall/1.0', ...(opts.headers || {}) }
    });
    clearTimeout(t);
    const text = await r.text().catch(() => null);
    return { status: r.status, headers: Object.fromEntries(r.headers.entries()), text };
  } catch (e) {
    return { error: String(e).slice(0, 300) };
  }
}

/* ------------- Inline hydration & script tag parsing ------------------- */

function extractHydrationBlobsFromHtml(html) {
  const blobs = [];
  const patterns = [
    /<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/ig,
    /<script[^>]+id=["']__NUXT__["'][^>]*>([\s\S]*?)<\/script>/ig,
    /<script[^>]*>\s*window\.__APOLLO_STATE__\s*=\s*(\{[\s\S]*?\})\s*;<\/script>/ig,
    /<script[^>]*>\s*window\.__INITIAL_STATE__\s*=\s*(\{[\s\S]*?\})\s*;<\/script>/ig,
    /<script[^>]*>\s*window\.__data\s*=\s*(\{[\s\S]*?\})\s*;<\/script>/ig
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(html)) !== null) {
      try { blobs.push(JSON.parse(m[1])); } catch { /* ignore */ }
    }
  }
  return blobs;
}

/* ------------------------------ Main ----------------------------------- */

(async () => {
  const targetSafe = safeName(TEST_URL);
  const targetOut = path.join(OUT_ROOT, targetSafe);
  ensureDir(targetOut);
  const shotsDir = path.join(targetOut, 'screenshots'); ensureDir(shotsDir);

  // Collected artifacts
  const findings = [];
  const jsonProbes = [];
  const headerChecks = [];
  const scriptUrls = [];
  const xhrScan = [];
  const altViews = [];
  const rawNotes = [];
  const mainRequest = { url: TEST_URL, headers: null, status: null, responseHeaders: null, csp: null, robots: null };

  // --- Launch browser with early hooks & CDP ---
  const launchOpts = { headless: !HEADFUL };
  const contextOpts = {};
  if (UA_OVERRIDE) contextOpts.userAgent = UA_OVERRIDE;

  const browser = await chromium.launch(launchOpts);
  const context = await browser.newContext(contextOpts);
  const page = await context.newPage();

  // 1) CDP session for early network observation (metadata only)
  const session = await context.newCDPSession(page);
  await session.send('Network.enable');
  await session.send('Page.enable');

  session.on('Network.requestWillBeSent', (ev) => {
    // We don’t store bodies here. Metadata only.
    if (ev.documentURL === TEST_URL && ev.type === 'Document') {
      mainRequest.headers = ev.request.headers || null;
    }
  });
  session.on('Network.responseReceived', (ev) => {
    if (ev.type === 'Document' && ev.response?.url?.split('#')[0] === TEST_URL.split('#')[0]) {
      mainRequest.status = ev.response.status;
      mainRequest.responseHeaders = ev.response.headers || null;
      mainRequest.csp = (ev.response.headers?.['content-security-policy'] || ev.response.headers?.['Content-Security-Policy']) || null;
      mainRequest.robots = (ev.response.headers?.['x-robots-tag'] || ev.response.headers?.['X-Robots-Tag']) || null;
    }
  });

  // 2) document_start style init script: instrument fetch/XHR (metadata only)
  await context.addInitScript(() => {
    // This runs before any page script (as close as possible).
    try {
      const _origFetch = window.fetch;
      window.fetch = async function(input, init) {
        try {
          const url = (typeof input === 'string') ? input : (input?.url || '');
          const method = (init && init.method) || 'GET';
          const body = (init && init.body) || null;
          let opName = null;
          if (method === 'POST' && body && typeof body === 'string' && body.length < 50000) {
            try { opName = (JSON.parse(body)||{}).operationName || null; } catch {}
          }
          window.__smoke_log && window.__smoke_log({ t:'fetch', url, method, opName });
        } catch {}
        return _origFetch.apply(this, arguments);
      };

      const _origOpen = XMLHttpRequest.prototype.open;
      const _origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        try { this.__smoke = { method, url }; } catch {}
        return _origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body) {
        try {
          if (body && typeof body === 'string' && body.length < 50000) {
            try { this.__smoke.opName = (JSON.parse(body)||{}).operationName || null; } catch {}
          }
          const info = this.__smoke || {};
          window.__smoke_log && window.__smoke_log({ t:'xhr', url: info.url, method: info.method, opName: info.opName });
        } catch {}
        return _origSend.apply(this, arguments);
      };

      // lightweight bus to page for Playwright to read
      window.__smoke_events = [];
      window.__smoke_log = (e) => { try { window.__smoke_events.push(e); } catch {} };

      // Observe one-time writes to common gating globals (metadata only)
      const watchKeys = ['piano', 'poool', 'meter', 'paywall', 'entitlement', 'subscribe', 'metering'];
      watchKeys.forEach((k) => {
        try {
          if (Object.prototype.hasOwnProperty.call(window, k)) return;
          let _val;
          Object.defineProperty(window, k, {
            configurable: true,
            set(v) { _val = v; try { window.__smoke_log({ t:'global_set', key: k, typeof: typeof v }); } catch {} },
            get() { return _val; }
          });
        } catch {}
      });
    } catch {}
  });

  // 3) Playwright-level response observer (JSON/GraphQL metadata)
  page.on('response', async (resp) => {
    try {
      const url = resp.url();
      const ct = (resp.headers()['content-type'] || '').toLowerCase();
      if (!/json|graphql/.test(ct)) return;

      const status = resp.status();
      const req = resp.request();
      const reqUrl = req.url();
      const method = req.method();

      let operationName = null;
      if (method === 'POST') {
        const pd = req.postData();
        if (pd && pd.length < 200000) {
          try { operationName = (JSON.parse(pd)||{}).operationName || null; } catch {}
        }
      }

      // Read small slice to extract top-level keys only (no full body saved)
      const text = await resp.text().catch(() => null);
      let keys = [];
      if (text) { try { const obj = JSON.parse(text); if (obj && typeof obj === 'object') keys = Object.keys(obj).slice(0, 30); } catch {} }

      xhrScan.push({
        url: reqUrl,
        method,
        status,
        ct,
        operationName,
        size: text ? text.length : null,
        topKeys: keys
      });

      if (text && hasArticleFieldsText(text)) {
        findings.push({
          id: 'xhr_article_like',
          title: 'XHR/GraphQL likely carries article HTML',
          severity: 'High',
          evidence: { url: reqUrl, status, ct, operationName, sampleKeys: keys }
        });
      }
    } catch {}
  });

  /* ----------------------------- Navigate ------------------------------- */
  try {
    await page.goto(TEST_URL, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
    await page.waitForTimeout(800);
  } catch (e) {
    rawNotes.push(`[nav] error: ${String(e).slice(0, 200)}`);
  }

  // Drain initScript events (fetch/xhr starts) — *metadata only*
  try {
    const early = await page.evaluate(() => (Array.isArray(window.__smoke_events) ? window.__smoke_events.splice(0) : []));
    if (early && early.length) {
      // Merge as "earlyHooks" in raw notes
      rawNotes.push({ earlyHooks: early.slice(0, 200) });
    }
  } catch {}

  // Screenshots (baseline → esc → scroll → hide overlays)
  try { await page.screenshot({ path: path.join(shotsDir, '01_baseline.png'), fullPage: true }); } catch {}
  try {
    const btn = page.locator(
      '#CybotCookiebotDialog [data-cybot="accept"], ' +
      '#CybotCookiebotDialog button:has-text("Allow all"), ' +
      'button:has-text("Tout accepter")'
    ).first();
    if (await btn.isVisible({ timeout: 1200 }).catch(() => false)) await btn.click().catch(() => {});
  } catch {}
  try { await page.keyboard.press('Escape').catch(() => {}); await page.waitForTimeout(300);
        await page.screenshot({ path: path.join(shotsDir, '02_after_escape.png'), fullPage: true }); } catch {}
  try {
    await page.evaluate(async () => { const s = (ms) => new Promise(r => setTimeout(r, ms));
      for (let i = 0; i < 6; i++) { window.scrollBy(0, window.innerHeight); await s(180); } window.scrollTo(0, 0);
    });
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(shotsDir, '03_after_scroll.png'), fullPage: true });
  } catch {}
  try {
    const cssHide = `${OVERLAYS.join(',')} { display:none !important; visibility:hidden !important } html,body{overflow:auto!important;height:auto!important}`;
    await page.addStyleTag({ content: cssHide });
    await page.waitForTimeout(350);
    await page.screenshot({ path: path.join(shotsDir, '04_after_css_hide.png'), fullPage: true });
  } catch {}

  /* ----------------------- Article-like DOM detection -------------------- */
  let articleDom = { sel: null, len: 0 };
  try {
    articleDom = await page.evaluate((sels) => {
      let best = { sel: null, len: 0 };
      for (const s of sels) {
        try {
          const el = document.querySelector(s);
          if (!el) continue;
          const t = (el.innerText || '').trim();
          if (t.length > best.len) best = { sel: s, len: t.length };
        } catch {}
      }
      return best;
    }, SELECTORS);
  } catch {}
  if (articleDom.len > 200) {
    findings.push({
      id: 'client_overlay',
      title: 'Client-side overlay (article present in DOM)',
      severity: 'High',
      evidence: { selector: articleDom.sel, length: articleDom.len }
    });
  }

  /* ------------------------- AMP & JSON-LD ------------------------------ */
  try {
    const ampHref = await page.evaluate(() => document.querySelector('link[rel="amphtml"]')?.href || null);
    if (ampHref) findings.push({ id: 'amp_variant', title: 'AMP variant advertised', severity: 'Info', evidence: { url: ampHref } });
  } catch {}

  try {
    const ld = await page.evaluate(() => {
      const out = [];
      for (const s of document.querySelectorAll('script[type="application/ld+json"]')) {
        try {
          const o = JSON.parse(s.textContent || '{}');
          const arr = Array.isArray(o) ? o : [o];
          for (const item of arr) {
            if (!item || typeof item !== 'object') continue;
            if (item['@type'] && String(item['@type']).toLowerCase().includes('article')) {
              out.push({ hasArticleBody: !!item.articleBody, keys: Object.keys(item).slice(0, 20) });
            }
          }
        } catch {}
      }
      return out;
    });
    if (ld && ld.some(x => x.hasArticleBody)) {
      findings.push({ id: 'jsonld_article', title: 'JSON-LD Article present', severity: 'Info', evidence: { count: ld.length, articleBodyAny: true } });
    } else if (ld && ld.length) {
      findings.push({ id: 'jsonld_present', title: 'JSON-LD present (non-articleBody)', severity: 'Info', evidence: { count: ld.length } });
    }
  } catch {}

  /* ------------------ Inline hydration & script src scan ----------------- */
  try {
    const html = await page.content();

    // <link rel="alternate" ... application/json|+json|oembed>
    try {
      const altJson = [...html.matchAll(/<link[^>]+rel=["']alternate["'][^>]+type=["']([^"']*json[^"']*)["'][^>]+href=["']([^"']+)["']/ig)]
        .slice(0, 10)
        .map(m => ({ type: m[1], href: new URL(m[2], TEST_URL).toString() }));
      if (altJson.length) findings.push({ id: 'alternate_json', title: 'Alternate JSON endpoints advertised', severity: 'Info', evidence: { links: altJson } });
    } catch {}

    const blobs = extractHydrationBlobsFromHtml(html);
    if (blobs.length) {
      const flagged = blobs.some(hasArticleFieldsObj);
      const sampleKeys = blobs.slice(0, 3).map(b => Object.keys(b || {}).slice(0, 20));
      findings.push({
        id: 'inline_hydration',
        title: 'Inline hydration JSON detected',
        severity: flagged ? 'High' : 'Info',
        evidence: { blobs: blobs.length, articleLike: flagged, sampleTopKeys: sampleKeys }
      });
    }

    // collect <script src=...>
    const re = /<script[^>]+src=(?:'|")([^'"]+)(?:'|")[^>]*>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      try { scriptUrls.push(new URL(m[1], TEST_URL).toString()); } catch {}
    }
  } catch {}

  // JS filenames with paywall-ish markers
  try {
    const pw = scriptUrls.filter(u => /paywall|gate|meter|subscribe|fr-gate|pay-wall|metering|piano|poool/i.test(u));
    if (pw.length) {
      findings.push({ id: 'paywall_js_candidates', title: 'Paywall-like JS filenames present', severity: 'Medium', evidence: { count: pw.length, samples: pw.slice(0, 20) } });
    }
    await writeJson(path.join(targetOut, 'js_scan.json'), scriptUrls);
  } catch {}

  // Print CSS hint
  try {
    const hasPrint = await page.evaluate(() => {
      try {
        return !!Array.from(document.styleSheets || []).find(ss => {
          try {
            if (ss.media && ss.media.mediaText && /print/i.test(ss.media.mediaText)) return true;
            return Array.from(ss.cssRules || []).some(r => r.media && /print/i.test(r.media?.mediaText || ''));
          } catch { return false; }
        });
      } catch { return false; }
    });
    if (hasPrint) findings.push({ id: 'print_css', title: 'Print stylesheet detected', severity: 'Info' });
  } catch {}

  // window globals
  try {
    const globals = await page.evaluate(() => {
      const keys = Object.getOwnPropertyNames(window);
      return keys.filter(k => /piano|poool|meter|paywall|entitlement|subscribe|metering/i.test(k)).slice(0, 100);
    });
    if (globals.length) findings.push({ id: 'global_flags', title: 'Potential metering/paywall globals on window', severity: 'Info', evidence: { keys: globals } });
  } catch {}

  // Service worker
  try {
    const swInfo = await page.evaluate(async () => {
      try {
        if (!('serviceWorker' in navigator)) return { supported: false };
        const regs = await navigator.serviceWorker.getRegistrations();
        return { supported: true, registrations: regs.map(r => ({ scope: r.scope })) };
      } catch (e) { return { supported: true, error: String(e) }; }
    });
    if (swInfo?.supported) findings.push({ id: 'service_worker', title: 'Service Worker present', severity: 'Info', evidence: swInfo });
  } catch {}

  /* -------------------------- URL Variants ------------------------------ */
  const variantMakers = [
    (u) => u.replace(/\/$/, '') + '/amp',
    (u) => u + (u.includes('?') ? '&' : '?') + 'print=1',
    (u) => u + (u.includes('?') ? '&' : '?') + 'share=1',
    (u) => u + (u.includes('?') ? '&' : '?') + 'outputType=amp'
  ];
  for (const make of variantMakers) {
    const v = make(TEST_URL);
    if (!v || v === TEST_URL) continue;
    const r = await fetchText(v, { headers: { 'Accept': 'text/html' }, timeout: 15000 });
    const ct = (r.headers?.['content-type'] || '').toLowerCase();
    const looksHtml = ct.includes('text/html') && (r.text || '').includes('<html');
    if (!r.error && r.status === 200 && looksHtml) altViews.push({ url: v, status: r.status });
  }
  if (altViews.length) findings.push({ id: 'alt_view', title: 'Alternative view available (print/share/amp)', severity: 'Low', evidence: { variants: altViews } });

  /* -------------------------- JSON Endpoint Probes ---------------------- */
  const jsonCandidates = [
    TEST_URL + '.json',
    TEST_URL.replace('/pages/', '/articles/') + '.json',
    TEST_URL.replace('/pages/', '/api/pages/'),
    TEST_URL + '?view=json',
    TEST_URL + '?format=json'
  ];
  const seen = new Set();
  for (const p of jsonCandidates) {
    if (!p || seen.has(p)) continue;
    seen.add(p);
    const r = await fetchText(p, { headers: { 'Accept': 'application/json' }, timeout: 15000 });
    jsonProbes.push({ path: p, status: r.status, headers: r.headers, snippet: short(r.text, 240) });

    if (r.error) continue;

    let parsed = null;
    if (isJsonCT(r)) { try { parsed = JSON.parse(r.text); } catch {} }

    if (parsed && hasArticleFieldsObj(parsed)) {
      findings.push({
        id: 'public_json',
        title: 'Public JSON endpoint exposing HTML-like content',
        severity: 'Critical',
        evidence: { path: p, contentType: r.headers?.['content-type'] }
      });
    } else if (r.status === 200 && !isJsonCT(r)) {
      findings.push({
        id: 'json_probe_html',
        title: 'Endpoint returned HTML (not JSON)',
        severity: 'Info',
        evidence: { path: p, contentType: r.headers?.['content-type'] }
      });
    }
  }

  /* ------------------------- UA / Referer Matrix ------------------------ */
  const headerMatrix = [
    { name: 'default',   opts: {} },
    { name: 'googlebot', opts: { userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' } },
    { name: 'ref_google',opts: { extraHTTPHeaders: { referer: 'https://www.google.com/' } } },
    { name: 'mobile_ios',opts: { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1' } },
    { name: 'facebook',  opts: { extraHTTPHeaders: { referer: 'https://m.facebook.com/' } } },
    { name: 'twitter',   opts: { extraHTTPHeaders: { referer: 'https://t.co/' } } },
  ];
  for (const h of headerMatrix) {
    try {
      const ctx = await browser.newContext(h.opts);
      const p = await ctx.newPage();
      await p.goto(TEST_URL, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
      await p.addStyleTag({ content: `${OVERLAYS.join(',')} { display:none !important } html,body{overflow:auto!important;height:auto!important}` }).catch(() => {});
      await p.waitForTimeout(250);
      const info = await p.evaluate((sels) => {
        for (const s of sels) {
          try {
            const el = document.querySelector(s);
            if (!el) continue;
            const t = (el.innerText || '').trim();
            if (t.length > 100) return { sel: s, len: t.length };
          } catch {}
        }
        return { sel: null, len: 0 };
      }, SELECTORS);
      headerChecks.push({ name: h.name, article: info });
      await ctx.close();
    } catch (e) {
      headerChecks.push({ name: h.name, error: String(e).slice(0, 200) });
    }
  }
  try {
    const baseLen = headerChecks.find(h => h.name === 'default')?.article?.len || 0;
    const diff = headerChecks
      .filter(h => h.name !== 'default' && (h.article?.len || 0) > baseLen + 200)
      .map(h => ({ name: h.name, exposed_len: h.article.len, base_len: baseLen }));
    if (diff.length) {
      findings.push({
        id: 'ua_referrer_bypass',
        title: 'UA/Referer-based rendered differences',
        severity: 'Medium',
        evidence: { diffs: diff }
      });
    }
  } catch {}

  /* ----------------------------- Save artifacts ------------------------- */
  try { await writeJson(path.join(targetOut, 'xhr_scan.json'), xhrScan); } catch {}
  try { await writeJson(path.join(targetOut, 'header_checks.json'), headerChecks); } catch {}
  try { await writeJson(path.join(targetOut, 'json_probes.json'), jsonProbes); } catch {}
  try { await writeJson(path.join(targetOut, 'raw_probes.json'), {
    target: TEST_URL,
    mainRequest,
    articleDom,
    altViews,
    notes: rawNotes
  }); } catch {}

  const report = {
    target: TEST_URL,
    generatedAt: new Date().toISOString(),
    artifacts: {
      screenshots: fs.existsSync(shotsDir) ? fs.readdirSync(shotsDir).map(f => path.join('screenshots', f)) : [],
      files: ['raw_probes.json', 'js_scan.json', 'xhr_scan.json', 'header_checks.json', 'json_probes.json'].filter(fn => fs.existsSync(path.join(targetOut, fn)))
    },
    findings
  };
  try { await writeJson(path.join(targetOut, 'report.json'), report); } catch (e) { console.error('write report failed:', e.message); }

  /* ---------------------------- Console summary ------------------------- */
  const summary = [];
  summary.push('');
  summary.push('=== smoke-paywall — summary ===');
  summary.push(`Target: ${TEST_URL}`);
  summary.push(`Main status: ${mainRequest.status || 'n/a'}`);
  summary.push(`CSP: ${mainRequest.csp ? 'present' : 'none'}`);
  summary.push(`Robots: ${mainRequest.robots || 'n/a'}`);
  if (articleDom.len > 0) summary.push(`DOM article candidate: ${articleDom.sel} (len≈${articleDom.len})`);
  const fx = (id) => findings.find(f => f.id === id);
  if (fx('public_json')) summary.push('Finding: public_json (Critical)');
  if (fx('xhr_article_like')) summary.push('Finding: xhr_article_like (High)');
  if (fx('inline_hydration')) summary.push('Finding: inline_hydration');
  if (fx('paywall_js_candidates')) summary.push('Finding: paywall_js_candidates');
  if (fx('ua_referrer_bypass')) summary.push('Finding: ua_referrer_bypass');
  if (fx('alt_view')) summary.push('Finding: alt_view');
  if (fx('jsonld_article')) summary.push('Finding: jsonld_article');
  console.log(summary.join('\n'));
  console.log('Artifacts dir:', targetOut);
  console.log('Report:', path.join(targetOut, 'report.json'));

  try { await context.close(); } catch {}
  try { await browser.close(); } catch {}
  process.exit(0);
})().catch(e => { console.error('Fatal:', e); process.exit(1); });