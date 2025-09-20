#!/usr/bin/env node
/**
 * smoke-paywall.js — defensive scanner (modified to dump full article content)
 *
 * What’s new in this build
 * - Deeper XHR/fragment analyzer:
 *     • watches XHR/fetch/GraphQL during page run
 *     • re-requests promising endpoints (var_ajax, HTML fragments, etc.)
 *     • captures FULL content for article-like responses (instead of 8 KB prefix)
 *     • computes article-like signals (text density, <p> ratio, presence of <article>, headings, common keys)
 *     • stores full content in a new artifact file
 * - Keeps the terminal summary, JSON + Markdown reports
 *
 * Use ONLY with explicit written authorization from the site owner.
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/* ------------------------------ CLI ------------------------------ */

function parseCLI() {
  const args = process.argv.slice(2);
  const getArg = (flag) => {
    const i = args.indexOf(flag);
    return (i !== -1 && args[i + 1] && !args[i + 1].startsWith('--')) ? args[i + 1] : null;
  };
  const url = getArg('--url') || process.env.TEST_URL || null;
  const headful = args.includes('--headful');
  const timeout = parseInt(getArg('--timeout') || '', 10);
  const ua = getArg('--ua') || null;
  const noPreview = args.includes('--no-preview');
  return {
    url, headful,
    timeout: Number.isFinite(timeout) ? timeout : 45000,
    userAgent: ua,
    noPreview
  };
}

const CFG = parseCLI();
if (!CFG.url) {
  console.error('ERROR: provide --url or TEST_URL env var');
  process.exit(2);
}

/* ---------------------------- Utilities --------------------------- */

function tsNow() { return new Date().toISOString().replace(/[:.]/g, '-'); }
function safeName(u) { return u.replace(/[^a-z0-9._-]+/gi, '_').slice(0, 160); }
function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }
async function writeJson(fp, obj) { await fs.promises.writeFile(fp, JSON.stringify(obj, null, 2), 'utf8'); }
async function writeText(fp, text) { await fs.promises.writeFile(fp, text, 'utf8'); }
function short(s, n = 240) { return (s || '').slice(0, n); }
function sha256(s) { return crypto.createHash('sha256').update(s || '').digest('hex'); }

const OUT_ROOT = `./smoke_paywall_${tsNow()}`; ensureDir(OUT_ROOT);

/* ----------------------------- Heuristics ------------------------- */

const SELECTORS = ['main', 'article', '.post-content', '.entry-content', '.page-content'];
const OVERLAYS = [
  '.fr-gate-overlay', '.fr-gate-container',
  '#CartDrawer-Overlay', 'cart-drawer',
  '#CybotCookiebotDialog', '.issue-article-cover'
];

const XHR_FRAGMENT_CANDIDATES = [
  'var_ajax=1',
  'view=fragment',
  'view=ajax',
  'render=fragment',
  '/fragment',
  '/partial',
  'component=ajax',
  'wp-admin/admin-ajax.php',
  '_format=amp',
  'format=amp',
  'outputType=amp'
];

const ARTICLE_KEYS_RX = /\b(body_html|articleBody|renderedBody|content_html|contentHtml|content\.blocks|paragraphs|paywall|meter|entitlement|subscribe)\b/i;
const HTML_LIKE_RX = /<html|<article|<main|<p[\s>]/i;

/* ----------------------------- HTTP helper ------------------------ */

async function fetchText(url, opts = {}) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), opts.timeout || 20000);
    const r = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': CFG.userAgent || 'smoke-paywall/1.1',
        ...(opts.headers || {})
      }
    });
    clearTimeout(t);
    const text = await r.text().catch(() => null);
    return { status: r.status, headers: Object.fromEntries(r.headers.entries()), text };
  } catch (e) {
    return { error: String(e).slice(0, 300) };
  }
}

/* Lightweight “article-like” signal on HTML content */
function analyzeHtmlContent(htmlContent) {
  const str = htmlContent || '';
  const len = str.length;

  const tagP = (str.match(/<p[\s>]/gi) || []).length;
  const tagH = (str.match(/<h[1-3][\s>]/gi) || []).length;
  const tagArticle = /<article[\s>]/i.test(str);
  const hasMain = /<main[\s>]/i.test(str);

  const textOnly = str
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const words = textOnly ? textOnly.split(/\s+/).filter(Boolean) : [];
  const wordCount = words.length;

  const density = len ? Math.min(1, wordCount / Math.max(200, len / 6)) : 0;

  const hasKeys = ARTICLE_KEYS_RX.test(str);
  const looksHtml = HTML_LIKE_RX.test(str);

  const articleLike =
    looksHtml &&
    (tagArticle || hasMain || tagP >= 8 || (wordCount >= 300 && density > 0.15));

  return {
    contentBytes: len,
    tagP,
    tagH,
    hasArticleTag: !!tagArticle,
    hasMain,
    wordCount,
    density: Number(density.toFixed(3)),
    hasArticleKeys: hasKeys,
    looksHtml,
    articleLike
  };
}

/* ----------------------------- Main flow -------------------------- */

(async () => {
  const targetSafe = safeName(CFG.url);
  const targetOut = path.join(OUT_ROOT, targetSafe); ensureDir(targetOut);
  const shotsDir = path.join(targetOut, 'screenshots'); ensureDir(shotsDir);
  const contentDir = path.join(targetOut, 'content'); ensureDir(contentDir);

  const findings = [];
  const jsonProbes = [];
  const headerChecks = [];
  const scriptUrls = [];
  const xhrScan = [];
  const altViews = [];
  const rawNotes = [];

  const launchOpts = { headless: !CFG.headful };
  const ctxOpts = {};
  if (CFG.userAgent) ctxOpts.userAgent = CFG.userAgent;

  const browser = await chromium.launch(launchOpts);
  const context = await browser.newContext(ctxOpts);
  const page = await context.newPage();

  /* --- Observe XHR/fetch/GraphQL while the page runs --- */
  page.on('response', async (resp) => {
    try {
      const req = resp.request();
      const url = req.url();
      const method = req.method();
      const status = resp.status();
      const ct = (resp.headers()['content-type'] || '').toLowerCase();

      if (!/json|graphql|html|text\/html/.test(ct)) return;

      let operationName = null;
      if (method === 'POST') {
        const body = req.postData();
        if (body && body.length < 200000) {
          try {
            const parsed = JSON.parse(body);
            operationName = parsed?.operationName || null;
          } catch {}
        }
      }

      let content = null;
      try {
        content = await resp.text();
      } catch {}

      const rec = {
        url,
        method,
        status,
        ct,
        operationName,
        size_hint: content ? content.length : null,
        sha256: content ? sha256(content) : null,
        preview: CFG.noPreview ? undefined : short(content || '', 180),
        topKeys: []
      };

      if (/json|graphql/.test(ct) && content) {
        try {
          const obj = JSON.parse(content);
          if (obj && typeof obj === 'object') {
            rec.topKeys = Object.keys(obj).slice(0, 30);
          }
        } catch {}
      }

      if (/html/.test(ct) && content) {
        const sig = analyzeHtmlContent(content);
        Object.assign(rec, { htmlSignals: sig });

        if (sig.articleLike) {
          const contentPath = path.join(contentDir, `xhr_${sha256(url).slice(0, 16)}.html`);
          await writeText(contentPath, content);
          findings.push({
            id: 'xhr_fragment_article_like',
            title: 'XHR/Fragment carries article HTML (full content saved)',
            severity: 'High',
            evidence: {
              url,
              ct,
              htmlSignals: sig,
              sha256: rec.sha256,
              contentPath: contentPath.replace(targetOut + '/', '')
            }
          });
        }
      }

      xhrScan.push(rec);
    } catch {}
  });

  /* --- Navigate --- */
  try {
    await page.goto(CFG.url, { waitUntil: 'domcontentloaded', timeout: CFG.timeout });
    await page.waitForTimeout(800);
  } catch (e) {
    rawNotes.push(`[nav] error: ${String(e).slice(0, 200)}`);
  }

  /* --- Basic diagnostics --- */
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

  /* --- Article node heuristic --- */
  let articleDom = { sel: null, len: 0, content: null };
  try {
    articleDom = await page.evaluate((sels) => {
      let best = { sel: null, len: 0, content: null };
      for (const s of sels) {
        try {
          const el = document.querySelector(s);
          if (!el) continue;
          const t = (el.innerText || '').trim();
          if (t.length > best.len) best = { sel: s, len: t.length, content: el.innerHTML };
        } catch {}
      }
      return best;
    }, SELECTORS);
    if (articleDom.len > 200 && articleDom.content) {
      const contentPath = path.join(contentDir, 'dom_article.html');
      await writeText(contentPath, articleDom.content);
      findings.push({
        id: 'client_overlay',
        title: 'Client-side overlay (article present in DOM, full content saved)',
        severity: 'High',
        evidence: { selector: articleDom.sel, length: articleDom.len, contentPath: contentPath.replace(targetOut + '/', '') }
      });
    }
  } catch {}

  /* --- HTML content + script inventory --- */
  try {
    const html = await page.content();

    const re = /<script[^>]+src=(?:'|")([^'"]+)(?:'|")[^>]*>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      try { scriptUrls.push(new URL(m[1], CFG.url).toString()); } catch {}
    }

    try {
      const ldCount = await page.evaluate(() => {
        let count = 0, body = 0;
        for (const s of document.querySelectorAll('script[type="application/ld+json"]')) {
          try {
            const o = JSON.parse(s.textContent || '{}');
            const arr = Array.isArray(o) ? o : [o];
            for (const item of arr) {
              if (item && typeof item === 'object' && String(item['@type'] || '').toLowerCase().includes('article')) {
                count++;
                if (item.articleBody) body++;
              }
            }
          } catch {}
        }
        return { count, withBody: body };
      });
      if (ldCount.count) {
        findings.push({
          id: ldCount.withBody ? 'jsonld_article' : 'jsonld_present',
          title: ldCount.withBody ? 'JSON-LD Article present' : 'JSON-LD present (non-articleBody)',
          severity: 'Info',
          evidence: ldCount
        });
      }
    } catch {}

  } catch {}

  /* --- Print CSS present? --- */
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

  /* --- window globals --- */
  try {
    const globals = await page.evaluate(() => {
      const keys = Object.getOwnPropertyNames(window);
      return keys.filter(k => /piano|poool|meter|paywall|entitlement|subscribe|metering/i.test(k)).slice(0, 100);
    });
    if (globals.length) {
      findings.push({ id: 'global_flags', title: 'Potential metering/paywall globals on window', severity: 'Info', evidence: { keys: globals } });
    }
  } catch {}

  /* --- Service Worker presence --- */
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

  /* --- Alternate views quick probes --- */
  const variantMakers = [
    (u) => u.replace(/\/$/, '') + '/amp',
    (u) => u + (u.includes('?') ? '&' : '?') + 'print=1',
    (u) => u + (u.includes('?') ? '&' : '?') + 'share=1',
    (u) => u + (u.includes('?') ? '&' : '?') + 'outputType=amp'
  ];
  for (const make of variantMakers) {
    const v = make(CFG.url);
    if (!v || v === CFG.url) continue;
    const r = await fetchText(v, { headers: { 'Accept': 'text/html' }, timeout: 15000 });
    const ct = (r.headers?.['content-type'] || '').toLowerCase();
    const looksHtml = ct.includes('text/html') && (r.text || '').includes('<html');
    if (!r.error && r.status === 200 && looksHtml) {
      const sig = analyzeHtmlContent(r.text);
      if (sig.articleLike) {
        const contentPath = path.join(contentDir, `alt_view_${sha256(v).slice(0, 16)}.html`);
        await writeText(contentPath, r.text);
        altViews.push({ url: v, status: r.status, contentPath: contentPath.replace(targetOut + '/', '') });
      } else {
        altViews.push({ url: v, status: r.status });
      }
    }
  }
  if (altViews.length) findings.push({ id: 'alt_view', title: 'Alternative view available (print/share/amp)', severity: 'Low', evidence: { variants: altViews } });

  /* --- JSON-ish naive probes --- */
  const jsonCandidates = [
    CFG.url + '.json',
    CFG.url.replace('/pages/', '/articles/') + '.json',
    CFG.url.replace('/pages/', '/api/pages/'),
    CFG.url + '?view=json',
    CFG.url + '?format=json'
  ];
  const seen = new Set();
  for (const p of jsonCandidates) {
    if (!p || seen.has(p)) continue;
    seen.add(p);
    const r = await fetchText(p, { headers: { 'Accept': 'application/json' }, timeout: 15000 });
    jsonProbes.push({ path: p, status: r.status, headers: r.headers, snippet: short(r.text, 240) });

    if (r.error) continue;

    const ct = (r.headers?.['content-type'] || '').toLowerCase();
    if (ct.includes('application/json') || ct.includes('+json')) {
      try {
        const parsed = JSON.parse(r.text);
        if (parsed && typeof parsed === 'object' && ARTICLE_KEYS_RX.test(JSON.stringify(parsed).slice(0, 40000))) {
          const contentPath = path.join(contentDir, `json_${sha256(p).slice(0, 16)}.json`);
          await writeText(contentPath, r.text);
          findings.push({
            id: 'public_json',
            title: 'Public JSON endpoint exposing HTML-like content (full content saved)',
            severity: 'Critical',
            evidence: { path: p, contentType: r.headers?.['content-type'], contentPath: contentPath.replace(targetOut + '/', '') }
          });
        }
      } catch {}
    } else if (r.status === 200 && !ct.includes('json')) {
      findings.push({
        id: 'json_probe_html',
        title: 'Endpoint returned HTML (not JSON)',
        severity: 'Info',
        evidence: { path: p, contentType: r.headers?.['content-type'] }
      });
    }
  }

  /* --- XHR follow-up: re-fetch promising fragment endpoints --- */
  for (const rec of xhrScan) {
    const isHtmlish = /html/.test(rec.ct || '');
    const looksFragment = XHR_FRAGMENT_CANDIDATES.some(s => (rec.url || '').includes(s));
    if (!isHtmlish && !looksFragment) continue;

    const r = await fetchText(rec.url, { headers: { 'Accept': rec.ct || 'text/html' }, timeout: 15000 });
    if (r.error || typeof r.text !== 'string') continue;

    const content = r.text;
    const sig = analyzeHtmlContent(content);

    rec.refetch = {
      status: r.status,
      ct: r.headers?.['content-type'] || null,
      sha256: sha256(content),
      htmlSignals: sig,
      preview: CFG.noPreview ? undefined : short(content, 180)
    };

    if (sig.articleLike) {
      const contentPath = path.join(contentDir, `xhr_refetch_${sha256(rec.url).slice(0, 16)}.html`);
      await writeText(contentPath, content);
      findings.push({
        id: 'xhr_fragment_article_like',
        title: 'XHR/Fragment carries article HTML (full content saved)',
        severity: 'High',
        evidence: {
          url: rec.url,
          ct: rec.refetch.ct,
          htmlSignals: sig,
          sha256: rec.refetch.sha256,
          contentPath: contentPath.replace(targetOut + '/', '')
        }
      });
    }
  }

  /* ----------------- Save artifacts ----------------- */
  try { await writeJson(path.join(targetOut, 'xhr_scan.json'), xhrScan); } catch {}
  try { await writeJson(path.join(targetOut, 'header_checks.json'), headerChecks); } catch {}
  try { await writeJson(path.join(targetOut, 'json_probes.json'), jsonProbes); } catch {}
  try { await writeJson(path.join(targetOut, 'js_scan.json'), scriptUrls); } catch {}
  try { await writeJson(path.join(targetOut, 'raw_probes.json'), {
    target: CFG.url, articleDom: { sel: articleDom.sel, len: articleDom.len }, altViews, notes: rawNotes
  }); } catch {}

  const report = {
    target: CFG.url,
    generatedAt: new Date().toISOString(),
    artifacts: {
      screenshots: fs.existsSync(shotsDir) ? fs.readdirSync(shotsDir).map(f => path.join('screenshots', f)) : [],
      content: fs.existsSync(contentDir) ? fs.readdirSync(contentDir).map(f => path.join('content', f)) : [],
      files: ['raw_probes.json', 'js_scan.json', 'xhr_scan.json', 'header_checks.json', 'json_probes.json']
        .filter(fn => fs.existsSync(path.join(targetOut, fn)))
    },
    findings
  };
  try { await writeJson(path.join(targetOut, 'report.json'), report); } catch (e) { console.error('write report failed:', e.message); }

  /* ----------------- Console summary ----------------- */
  function table(rows, headers) {
    const all = [headers, ...rows];
    const widths = headers.map((_, i) => Math.max(...all.map(r => String(r[i]).length)));
    const line = (r) => '| ' + r.map((c, i) => String(c).padEnd(widths[i], ' ')).join(' | ') + ' |';
    const sep = '+-' + widths.map(w => '-'.repeat(w)).join('-+-') + '-+';
    return [sep, line(headers), sep, ...rows.map(line), sep].join('\n');
  }

  const sevCount = findings.reduce((m, f) => (m[f.severity] = (m[f.severity] || 0) + 1, m), {});
  const sevRows = Object.entries(sevCount).sort((a,b)=>a[0].localeCompare(b[0])).map(([sev,c], idx)=>[idx, `'${sev}'`, c]);

  console.log('\n=== Findings summary ===\n');
  console.log(table(sevRows, ['index','Severity','Count']));

  const top = findings.slice(0, 12).map((f, i) => [i, `'${f.id}'`, `'${f.title}'`, `'${f.severity}'`]);
  console.log('\nTop findings (first 12):\n');
  console.log(table(top, ['(index)','id','title','severity']));

  console.log(`\nArtifacts dir: ${targetOut}`);
  console.log(`Report (JSON): ${path.join(targetOut, 'report.json')}`);
  console.log(`Content dir: ${contentDir}`);

  const md = [
    `# Smoke report for ${CFG.url}`,
    '',
    '## Findings',
    '',
    ...findings.map(f => {
      const contentPath = f.evidence?.contentPath ? ` [Content: ${f.evidence.contentPath}]` : '';
      return `- **${f.severity}** — ${f.title} (${f.id})${contentPath}`;
    })
  ].join('\n');
  const mdPath = path.join(targetOut, 'report.md');
  try { await fs.promises.writeFile(mdPath, md, 'utf8'); } catch {}
  console.log(`Report (Markdown): ${mdPath}`);

  console.log('\nScan complete. Stay responsible — only test with written authorization.\n');

  try { await context.close(); } catch {}
  try { await browser.close(); } catch {}
  process.exit(0);
})().catch(e => { console.error('Fatal:', e); process.exit(1); });