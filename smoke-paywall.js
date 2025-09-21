#!/usr/bin/env node
/**
 * smoke-paywall.js — paywall scanner
 *
 * Use ONLY with explicit written authorization from the site owner.
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const urlModule = require('url');

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
function decodeUtf8(str) { return decodeURIComponent(escape(str)); }
function parseHtmlEntities(encodedString) {
  const textarea = document.createElement('textarea');
  textarea.innerHTML = encodedString;
  return textarea.value;
}
function breakText(str, headers = false) {
  str = str.replace(/(?:^|[A-Za-z\"\“\”\)])(\.+|\?|!)(?=[A-ZÖÜ\„\”\d][A-Za-zÀ-ÿ\„\d]{1,})/gm, "$&\n\n");
  if (headers) str = str.replace(/(([a-z]{2,}|[\"\“]))(?=[A-Z](?=[A-Za-zÀ-ÿ]+))/gm, "$&\n\n");
  return str;
}
function matchDomain(domains, hostname) {
  if (typeof domains === 'string') domains = [domains];
  return domains.find(domain => hostname === domain || hostname.endsWith('.' + domain)) || false;
}
function urlHost(url) {
  if (/^http/.test(url)) {
    try { return new URL(url).hostname; } catch (e) {}
  }
  return url;
}
function matchUrlDomain(domains, url) { return matchDomain(domains, urlHost(url)); }

/* Recursive JSON key finder for nested content */
function findKeyJson(obj, keyRegex, maxDepth = 5, currentDepth = 0) {
  if (currentDepth > maxDepth) return null;
  if (typeof obj !== 'object' || obj === null) return null;
  for (const key in obj) {
    if (keyRegex.test(key)) return obj[key];
    const nested = findKeyJson(obj[key], keyRegex, maxDepth, currentDepth + 1);
    if (nested) return nested;
  }
  return null;
}

/* Console table formatter */
function table(rows, headers) {
  const all = [headers, ...rows];
  const widths = headers.map((_, i) => Math.max(...all.map(r => String(r[i] || '').length)));
  const line = (r) => '| ' + r.map((c, i) => String(c || '').padEnd(widths[i], ' ')).join(' | ') + ' |';
  const sep = '+-' + widths.map(w => '-'.repeat(w)).join('-+-') + '-+';
  return [sep, line(headers), sep, ...rows.map(line), sep].join('\n');
}

const OUT_ROOT = `./smoke_paywall_${tsNow()}`; ensureDir(OUT_ROOT);

/* ----------------------------- Heuristics ------------------------- */

const SELECTORS = [
  'main', 'article', '.post-content', '.entry-content', '.page-content',
  'div.article-body', 'div.content-body', 'div.meteredContent',
  'div.body-copy', 'div.article-main-txt', '#articleBody', 'p#articleBodyForbidden'
];
const OVERLAYS = [
  '.fr-gate-overlay', '.fr-gate-container',
  '#CartDrawer-Overlay', 'cart-drawer',
  '#CybotCookiebotDialog', '.issue-article-cover',
  'div.paywall', 'div#paywall', 'div.premium', 'div[class*="-premium"]',
  'div[id^="issuem-leaky-paywall-"]', 'div.wkwp-paywall',
  'div.didomi-popup-open', 'div.OUTBRAIN', 'div[id^="taboola-"]'
];

const XHR_FRAGMENT_CANDIDATES = [
  'var_ajax=1', 'view=fragment', 'view=ajax', 'render=fragment',
  '/fragment', '/partial', 'component=ajax', 'wp-admin/admin-ajax.php',
  '_format=amp', 'format=amp', 'outputType=amp',
  '/wp-json/wp/v2/posts/', '/?rest_route=/wp/v2/posts/'
];

const ARTICLE_KEYS_RX = /\b(body_html|articleBody|renderedBody|content_html|contentHtml|content\.blocks|paragraphs|paywall|meter|entitlement|subscribe|content\.rendered|blocks|body|text)\b/i;
const HTML_LIKE_RX = /<html|<article|<main|<p[\s>]/i;
const JSON_LD_RX = /<script type="application\/ld\+json">([\s\S]+?)<\/script>/gi;
const NEXT_DATA_RX = /<script id="__NEXT_DATA__"[^>]*>([\s\S]+?)<\/script>/gi;

/* Paywall provider markers for detection */
const PROVIDER_MARKERS = {
  medium: 'head > link[href*=".medium.com/"]',
  beehiiv: 'head > meta[property="og:image"][content*="beehiiv"]',
  ghost: 'head > meta[name="generator"][content^="Ghost"]',
  substack: 'head > link[href^="https://substackcdn.com/"]',
  leaky_paywall: 'head > link[href*="/leaky-paywall"], script[src*="/leaky-paywall"], div[id^="issuem-leaky-paywall-"]',
  wallkit: 'head > link[href$=".wallkit.net"]'
};

/* Blocked script regexes for paywall detection */
const BLOCKED_REGEXES = {
  piano: /piano\.io\/.*\.js/,
  poool: /poool\.io\/.*\.js/,
  outbrain: /outbrain\.com\/.*\.js/,
  taboola: /taboola\.com\/.*\.js/
};

/* Paywall strings for false positive validation */
const PAYWALL_STRINGS_RX = /abonn[ée]?|subscribe|login|sign in|réservée aux|paywall|premium content|metered/i;

/* ----------------------------- HTTP helper ------------------------ */

async function fetchText(url, opts = {}) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), opts.timeout || 20000);
    const r = await fetch(url, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': opts.ua || CFG.userAgent || 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Referer': opts.referer || 'https://www.google.com/',
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

/* Enhanced article-like signal with false positive filtering */
function analyzeHtmlContent(htmlContent, teaserLength = 0) {
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
  const isPaywallContent = PAYWALL_STRINGS_RX.test(textOnly);
  const hasSubscriptionPrompt = /subscribe|login|sign in|réservée|abonn[ée]/.test(textOnly);

  // Stricter criteria to reduce false positives
  const articleLike =
    looksHtml &&
    !isPaywallContent &&
    !hasSubscriptionPrompt &&
    wordCount > 1000 && // Higher threshold
    density > 0.3 && // Tighter density
    len > (teaserLength * 2) && // Significantly longer than teaser
    (tagArticle || hasMain || (tagP >= 12 && tagH >= 3)); // Stricter tag requirements

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
    isPaywallContent,
    hasSubscriptionPrompt,
    articleLike,
    validationScore: articleLike ? 'HIGH' : isPaywallContent ? 'PAYWALLED' : 'LOW'
  };
}

/* Extract article from JSON with recursive key finding */
function extractJsonContent(jsonStr, isNextData = false) {
  try {
    const json = JSON.parse(jsonStr);
    let content = '';
    if (isNextData) {
      const body = findKeyJson(json, /body|blocks|content/i);
      if (Array.isArray(body)) {
        content = body.map(b => b.text || (b.children ? b.children.map(c => c.text).join('') : '')).join('\n\n');
      } else if (typeof body === 'string') {
        content = body;
      }
    } else {
      const arr = Array.isArray(json) ? json : [json];
      for (const item of arr) {
        const articleBody = findKeyJson(item, /articlebody|text/i);
        if (articleBody) content += breakText(parseHtmlEntities(articleBody)) + '\n\n';
      }
    }
    return content.trim();
  } catch {}
  return '';
}

/* Full archive flow with polling */
async function fetchArchiveContent(url) {
  try {
    const submitUrl = `https://archive.is/submit/?url=${encodeURIComponent(url)}`;
    const submitRes = await fetchText(submitUrl, { timeout: 30000 });
    if (submitRes.error || !submitRes.text) return null;
    
    // Extract snapshot URL from response
    const snapshotMatch = submitRes.text.match(/href="https:\/\/archive\.is\/(\w+)\/[^"]+"/);
    if (snapshotMatch) {
      const snapshotUrl = `https://archive.is/${snapshotMatch[1]}`;
      let attempts = 0;
      while (attempts < 5) {
        const snapshotRes = await fetchText(snapshotUrl, { timeout: 15000 });
        if (snapshotRes.status === 200 && snapshotRes.text && snapshotRes.text.includes('<article')) return snapshotRes.text;
        await new Promise(r => setTimeout(r, 5000)); // Poll every 5s
        attempts++;
      }
    }
  } catch (e) {
    console.log(`Archive fetch error: ${e.message}`);
  }
  return null;
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

  console.log(`🚀 Starting scan for: ${CFG.url}`);
  console.log(`Output directory: ${targetOut}`);

  /* --- Get initial teaser length for validation --- */
  let teaserLength = 0;
  try {
    await page.goto(CFG.url, { waitUntil: 'domcontentloaded', timeout: CFG.timeout });
    await page.waitForTimeout(800);
    
    const teaserHtml = await page.content();
    const teaserSig = analyzeHtmlContent(teaserHtml);
    teaserLength = teaserSig.contentBytes;
    console.log(`Teaser baseline: ${teaserSig.wordCount} words, ${teaserSig.contentBytes} bytes`);
  } catch (e) {
    rawNotes.push(`[nav] error: ${String(e).slice(0, 200)}`);
  }

  /* --- Detect paywall provider --- */
  let detectedProvider = null;
  try {
    detectedProvider = await page.evaluate((markers) => {
      for (const [provider, sel] of Object.entries(markers)) {
        if (document.querySelector(sel)) return provider;
      }
      return null;
    }, PROVIDER_MARKERS);
    if (detectedProvider) {
      findings.push({
        id: 'paywall_provider',
        title: `Detected paywall provider: ${detectedProvider}`,
        severity: 'Info',
        evidence: { provider: detectedProvider }
      });
      console.log(`Detected provider: ${detectedProvider}`);
    }
  } catch {}

  /* --- Block paywall scripts --- */
  try {
    const html = await page.content();
    const re = /<script[^>]+src=(?:'|")([^'"]+)(?:'|")[^>]*>/gi;
    let m;
    while ((m = re.exec(html)) !== null) {
      try { scriptUrls.push(new URL(m[1], CFG.url).toString()); } catch {}
    }

    const blockedScripts = scriptUrls.filter(url => Object.values(BLOCKED_REGEXES).some(rx => rx.test(url)));
    if (blockedScripts.length > 0) {
      await page.evaluate((urls) => {
        document.querySelectorAll('script[src]').forEach(script => {
          if (urls.includes(script.src)) script.remove();
        });
      }, blockedScripts);
      findings.push({
        id: 'blocked_scripts',
        title: `Blocked ${blockedScripts.length} paywall scripts`,
        severity: 'Medium',
        evidence: { scripts: blockedScripts.slice(0, 5) }
      });
      console.log(`Blocked ${blockedScripts.length} paywall scripts`);
      await page.reload({ waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(800);
    }
  } catch {}

  /* --- Cookie domain testing --- */
  let cookieDomain = null;
  try {
    cookieDomain = await page.evaluate((hostname) => {
      let domain = hostname;
      let n = 0;
      let parts = hostname.split('.');
      let str = '_gd' + Date.now();
      while (n < (parts.length - 1) && document.cookie.indexOf(str + '=' + str) === -1) {
        domain = parts.slice(-1 - (++n)).join('.');
        document.cookie = str + "=" + str + ";domain=" + domain + ";";
      }
      document.cookie = str + "=;expires=Thu, 01 Jan 1970 00:00:01 GMT;domain=" + domain + ";";
      return domain;
    }, new URL(CFG.url).hostname);
    if (cookieDomain) {
      findings.push({
        id: 'cookie_domain',
        title: 'Detected effective cookie domain',
        severity: 'Info',
        evidence: { domain: cookieDomain }
      });
    }
  } catch {}

  /* --- Dynamic content watching --- */
  try {
    await page.evaluate((sels, overlays) => {
      new MutationObserver((mutations) => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === 1) {
              if (overlays.some(sel => node.matches(sel))) {
                node.remove();
              }
              if (sels.some(sel => node.matches(sel))) {
                node.style.display = '';
                node.classList.remove('meteredContent', 'composer-content');
              }
            }
          }
        }
      }).observe(document.body, { childList: true, subtree: true });
    }, SELECTORS, OVERLAYS);
    findings.push({
      id: 'dynamic_watcher',
      title: 'Activated dynamic content monitoring',
      severity: 'Medium'
    });
    console.log(`👁️  Dynamic content watcher active`);
  } catch {}

  /* --- Inject override scripts --- */
  try {
    await page.evaluate(() => {
      if (window.Fusion) window.Fusion.globalContent.isPremium = false;
      if (window.piano) window.piano.user.isSubscribed = true;
      if (window.poool) window.poool.user.hasAccess = true;
    });
    await page.waitForTimeout(500);
    findings.push({
      id: 'script_injection',
      title: 'Injected global overrides',
      severity: 'Medium'
    });
    console.log(`Injected global overrides`);
  } catch {}

  /* --- Cookie reset cycles --- */
  try {
    for (let i = 0; i < 3; i++) {
      await page.evaluate(() => localStorage.clear());
      await page.evaluate(() => sessionStorage.clear());
      await page.reload({ waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(500);
    }
    findings.push({
      id: 'cookie_reset',
      title: 'Completed cookie reset cycles',
      severity: 'Medium'
    });
    console.log(`Completed ${3} cookie reset cycles`);
  } catch {}

  /* --- Reader mode emulation --- */
  try {
    const readerCss = `
      body { font-family: serif; font-size: 18px; max-width: 800px; margin: 0 auto; }
      .paywall, [class*="subscribe"], [id*="gate"], [class*="premium"], .meteredContent { 
        display: none !important; 
      }
      article, main, .content, .article-body { 
        display: block !important; 
        overflow: visible !important; 
        max-height: none !important;
      }
      .composer-content { visibility: visible !important; }
    `;
    await page.addStyleTag({ content: readerCss });
    await page.waitForTimeout(500);
    findings.push({
      id: 'reader_mode',
      title: 'Applied reader mode CSS',
      severity: 'Medium'
    });
    console.log(`Reader mode CSS applied`);
  } catch {}

  /* --- Baseline screenshot --- */
  try { 
    await page.screenshot({ path: path.join(shotsDir, '01_baseline.png'), fullPage: true }); 
    console.log(`Baseline screenshot saved`);
  } catch {}

  /* --- AMP unhide detection --- */
  try {
    const ampHtml = await page.evaluate(() => document.querySelector('link[rel="amphtml"]')?.href);
    if (ampHtml) {
      const ampRes = await fetchText(ampHtml, { ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' });
      if (ampRes.text) {
        const sig = analyzeHtmlContent(ampRes.text, teaserLength);
        if (sig.articleLike) {
          const contentPath = path.join(contentDir, 'amp_unhide.html');
          await writeText(contentPath, ampRes.text);
          findings.push({
            id: 'amp_unhide',
            title: 'Full AMP content extracted',
            severity: 'High',
            evidence: { url: ampHtml, contentPath: contentPath.replace(targetOut + '/', '') }
          });
          console.log(`⚡ AMP content found: ${sig.wordCount} words`);
        }
      }
    }
  } catch {}

  /* --- Alternative JSON URL probing --- */
  try {
    const jsonUrlCandidates = [
      CFG.url + '?format=json',
      CFG.url + '?view=json',
      path.dirname(CFG.url) + '/wp-json/oembed/1.0/embed?url=' + encodeURIComponent(CFG.url),
      CFG.url.replace('/post/', '/api/post/'),
      CFG.url.replace('/article/', '/api/article/')
    ];
    
    for (const jsonUrl of jsonUrlCandidates) {
      const r = await fetchText(jsonUrl);
      if (r.text) {
        try {
          const json = JSON.parse(r.text);
          const articleText = findKeyJson(json, ARTICLE_KEYS_RX);
          if (articleText && typeof articleText === 'string' && articleText.length > 1000) {
            const cleaned = breakText(parseHtmlEntities(articleText));
            const contentPath = path.join(contentDir, `json_url_${sha256(jsonUrl).slice(0, 8)}.txt`);
            await writeText(contentPath, cleaned);
            findings.push({
              id: 'json_url',
              title: 'Full content from JSON API',
              severity: 'Critical',
              evidence: { url: jsonUrl, contentPath: contentPath.replace(targetOut + '/', '') }
            });
            console.log(`🔗 JSON API success: ${articleText.length} chars`);
            break;
          }
        } catch {}
      }
    }
  } catch {}

  /* --- XHR Response Monitoring --- */
  page.on('response', async (resp) => {
    try {
      const req = resp.request();
      const url = req.url();
      const method = req.method();
      const status = resp.status();
      const ct = (resp.headers()['content-type'] || '').toLowerCase();

      if (!/json|graphql|html|text\/html/.test(ct)) return;

      let content = null;
      try {
        content = await resp.text();
      } catch {}

      const rec = {
        url,
        method,
        status,
        ct,
        size_hint: content ? content.length : null,
        sha256: content ? sha256(content) : null,
        preview: CFG.noPreview ? undefined : short(content || '', 180),
        topKeys: []
      };

      if (/json|graphql/.test(ct) && content) {
        try {
          const obj = JSON.parse(content);
          if (obj && typeof obj === 'object') {
            rec.topKeys = Object.keys(obj).slice(0, 10);
            const articleText = findKeyJson(obj, ARTICLE_KEYS_RX);
            if (articleText && typeof articleText === 'string' && articleText.length > 1000) {
              const cleaned = breakText(parseHtmlEntities(articleText));
              const contentPath = path.join(contentDir, `xhr_json_${sha256(url).slice(0, 8)}.txt`);
              await writeText(contentPath, cleaned);
              findings.push({
                id: 'xhr_json',
                title: 'Full article from XHR JSON',
                severity: 'High',
                evidence: { url, contentPath: contentPath.replace(targetOut + '/', '') }
              });
              console.log(`XHR JSON hit: ${articleText.length} chars`);
            }
          }
        } catch {}
      }

      if (/html/.test(ct) && content) {
        const sig = analyzeHtmlContent(content, teaserLength);
        Object.assign(rec, { htmlSignals: sig });

        if (sig.articleLike) {
          const contentPath = path.join(contentDir, `xhr_${sha256(url).slice(0, 16)}.html`);
          await writeText(contentPath, content);
          findings.push({
            id: 'xhr_fragment',
            title: `XHR fragment success (${sig.validationScore})`,
            severity: 'High',
            evidence: {
              url,
              ct,
              htmlSignals: sig,
              sha256: rec.sha256,
              contentPath: contentPath.replace(targetOut + '/', '')
            }
          });
          console.log(`🌐 XHR fragment: ${sig.wordCount} words (${sig.validationScore})`);
        }
      }

      xhrScan.push(rec);
    } catch {}
  });

  /* --- Random UA/Referer rotation --- */
  const uas = [
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  ];
  const referers = ['https://www.google.com/', 'https://www.facebook.com/', 'https://t.co/', 'https://twitter.com/'];

  try {
    for (const ua of uas) {
      for (const referer of referers) {
        const r = await fetchText(CFG.url, { ua, referer, timeout: 10000 });
        if (r.text && r.status === 200) {
          const sig = analyzeHtmlContent(r.text, teaserLength);
          if (sig.articleLike) {
            const contentPath = path.join(contentDir, `ua_referer_${sha256(ua + referer).slice(0, 16)}.html`);
            await writeText(contentPath, r.text);
            findings.push({
              id: 'ua_referer_bypass',
              title: `UA/Referer bypass success (${sig.validationScore})`,
              severity: 'High',
              evidence: { ua: short(ua), referer, contentPath: contentPath.replace(targetOut + '/', '') }
            });
            console.log(`🎭 UA/Referer success: ${sig.wordCount} words`);
            break;
          }
        }
      }
      if (findings.some(f => f.id === 'ua_referer_bypass')) break;
    }
  } catch {}

  /* --- Archive bypass --- */
  try {
    console.log('Probing archive services...');
    const archiveContent = await fetchArchiveContent(CFG.url);
    if (archiveContent) {
      const sig = analyzeHtmlContent(archiveContent, teaserLength);
      if (sig.articleLike) {
        const contentPath = path.join(contentDir, 'archive_bypass.html');
        await writeText(contentPath, archiveContent);
        findings.push({
          id: 'archive_bypass',
          title: `Archive bypass success (${sig.validationScore})`,
          severity: 'Critical',
          evidence: { contentPath: contentPath.replace(targetOut + '/', '') }
        });
        console.log(`🏆 Archive bypass: ${sig.wordCount} words`);
      }
    }
  } catch {}

  /* --- Alternative view probing --- */
  const variantMakers = [
    (u) => u.replace(/\/$/, '') + '/amp',
    (u) => u + (u.includes('?') ? '&' : '?') + 'print=1',
    (u) => u + (u.includes('?') ? '&' : '?') + 'share=1',
    (u) => u + (u.includes('?') ? '&' : '?') + 'outputType=amp',
    (u) => u + (u.includes('?') ? '&' : '?') + '_format=amp'
  ];

  for (const make of variantMakers) {
    const v = make(CFG.url);
    if (!v || v === CFG.url) continue;
    const r = await fetchText(v, { headers: { 'Accept': 'text/html' }, timeout: 10000 });
    const ct = (r.headers?.['content-type'] || '').toLowerCase();
    const looksHtml = ct.includes('text/html') && (r.text || '').includes('<html');
    if (!r.error && r.status === 200 && looksHtml) {
      const sig = analyzeHtmlContent(r.text, teaserLength);
      if (sig.articleLike) {
        const contentPath = path.join(contentDir, `alt_view_${sha256(v).slice(0, 16)}.html`);
        await writeText(contentPath, r.text);
        altViews.push({ url: v, status: r.status, contentPath: contentPath.replace(targetOut + '/', '') });
        findings.push({
          id: 'alt_view',
          title: `Alternative view success (${sig.validationScore})`,
          severity: 'High',
          evidence: { url: v, contentPath: contentPath.replace(targetOut + '/', '') }
        });
        console.log(`🔄 Alt view success: ${sig.wordCount} words`);
      } else {
        altViews.push({ url: v, status: r.status });
      }
    }
  }

  /* --- JSON endpoint probing --- */
  const jsonCandidates = [
    CFG.url + '.json',
    CFG.url.replace('/pages/', '/articles/') + '.json',
    CFG.url.replace('/pages/', '/api/pages/'),
    CFG.url + '?view=json',
    CFG.url + '?format=json',
    path.dirname(CFG.url) + '/wp-json/wp/v2/posts/' + path.basename(CFG.url),
    CFG.url + '?rest_route=/wp/v2/posts/' + path.basename(CFG.url)
  ];
  
  const seen = new Set();
  for (const p of jsonCandidates) {
    if (!p || seen.has(p)) continue;
    seen.add(p);
    const r = await fetchText(p, { headers: { 'Accept': 'application/json' }, timeout: 10000 });
    jsonProbes.push({ path: p, status: r.status, headers: r.headers, snippet: short(r.text, 240) });

    if (r.error) continue;

    const ct = (r.headers?.['content-type'] || '').toLowerCase();
    if (ct.includes('application/json') || ct.includes('+json')) {
      try {
        const parsed = JSON.parse(r.text);
        if (parsed && typeof parsed === 'object') {
          const articleText = findKeyJson(parsed, ARTICLE_KEYS_RX);
          if (articleText && typeof articleText === 'string' && articleText.length > 1000) {
            const cleaned = breakText(parseHtmlEntities(articleText));
            const contentPath = path.join(contentDir, `json_probe_${sha256(p).slice(0, 8)}.txt`);
            await writeText(contentPath, cleaned);
            findings.push({
              id: 'public_json',
              title: `Public JSON endpoint success (${articleText.length} chars)`,
              severity: 'Critical',
              evidence: { path: p, contentType: r.headers?.['content-type'], contentPath: contentPath.replace(targetOut + '/', '') }
            });
            console.log(`📄 JSON probe success: ${articleText.length} chars`);
          }
        }
      } catch {}
    }
  }

  /* --- DOM Article Extraction --- */
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
    
    if (articleDom.len > 500) { // Higher threshold
      const contentHtml = articleDom.content || '';
      const sig = analyzeHtmlContent(contentHtml, teaserLength);
      if (sig.articleLike) {
        const cleaned = breakText(parseHtmlEntities(contentHtml));
        const contentPath = path.join(contentDir, 'dom_article.html');
        await writeText(contentPath, cleaned);
        findings.push({
          id: 'dom_article',
          title: `DOM article extraction success (${sig.validationScore})`,
          severity: 'High',
          evidence: { selector: articleDom.sel, length: articleDom.len, contentPath: contentPath.replace(targetOut + '/', '') }
        });
        console.log(`🏠 DOM extraction: ${sig.wordCount} words (${sig.validationScore})`);
      }
    }
  } catch {}

  /* --- JSON-LD and Next.js extraction --- */
  try {
    const html = await page.content();

    // JSON-LD extraction
    let jsonLdContent = '';
    let ldMatch;
    while ((ldMatch = JSON_LD_RX.exec(html)) !== null) {
      jsonLdContent += extractJsonContent(ldMatch[1]) + '\n\n';
    }
    if (jsonLdContent.length > 1000) {
      const contentPath = path.join(contentDir, 'json_ld_extracted.txt');
      await writeText(contentPath, jsonLdContent);
      findings.push({
        id: 'jsonld_extracted',
        title: 'Full content from JSON-LD',
        severity: 'High',
        evidence: { contentPath: contentPath.replace(targetOut + '/', '') }
      });
      console.log(`💎 JSON-LD extraction: ${jsonLdContent.length} chars`);
    }

    // Next.js __NEXT_DATA__ extraction
    let nextDataContent = '';
    let nextMatch;
    while ((nextMatch = NEXT_DATA_RX.exec(html)) !== null) {
      nextDataContent += extractJsonContent(nextMatch[1], true) + '\n\n';
    }
    if (nextDataContent.length > 1000) {
      const contentPath = path.join(contentDir, 'next_data_extracted.txt');
      await writeText(contentPath, nextDataContent);
      findings.push({
        id: 'next_data_extracted',
        title: 'Full content from Next.js data',
        severity: 'High',
        evidence: { contentPath: contentPath.replace(targetOut + '/', '') }
      });
      console.log(`⚛️ Next.js extraction: ${nextDataContent.length} chars`);
    }

    // JSON-LD count for reporting
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
        title: ldCount.withBody ? 'JSON-LD Article with body' : 'JSON-LD Article metadata only',
        severity: ldCount.withBody ? 'High' : 'Info',
        evidence: ldCount
      });
    }
  } catch {}

  /* --- Print CSS detection --- */
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
    if (hasPrint) {
      findings.push({ 
        id: 'print_css', 
        title: 'Print stylesheet detected', 
        severity: 'Info' 
      });
    }
  } catch {}

  /* --- Window globals detection --- */
  try {
    const globals = await page.evaluate(() => {
      const keys = Object.getOwnPropertyNames(window);
      return keys.filter(k => /piano|poool|meter|paywall|entitlement|subscribe|metering/i.test(k)).slice(0, 20);
    });
    if (globals.length) {
      findings.push({ 
        id: 'global_flags', 
        title: `Found ${globals.length} paywall globals`, 
        severity: 'Info', 
        evidence: { keys: globals } 
      });
    }
  } catch {}

  /* --- Service Worker detection --- */
  try {
    const swInfo = await page.evaluate(async () => {
      try {
        if (!('serviceWorker' in navigator)) return { supported: false };
        const regs = await navigator.serviceWorker.getRegistrations();
        return { supported: true, registrations: regs.map(r => ({ scope: r.scope })) };
      } catch (e) { return { supported: true, error: String(e) }; }
    });
    if (swInfo?.supported) {
      findings.push({ 
        id: 'service_worker', 
        title: 'Service Worker present', 
        severity: 'Info', 
        evidence: swInfo 
      });
    }
  } catch {}

  /* --- Final screenshots --- */
  try {
    await page.evaluate(async () => { 
      const s = (ms) => new Promise(r => setTimeout(r, ms));
      for (let i = 0; i < 3; i++) { 
        window.scrollBy(0, window.innerHeight); 
        await s(200); 
      } 
      window.scrollTo(0, 0);
    });
    await page.waitForTimeout(300);
    await page.screenshot({ path: path.join(shotsDir, '02_after_scroll.png'), fullPage: true });
    
    const finalCss = `${OVERLAYS.join(',')} { display:none !important; visibility:hidden !important } html,body{overflow:auto!important;height:auto!important}`;
    await page.addStyleTag({ content: finalCss });
    await page.waitForTimeout(350);
    await page.screenshot({ path: path.join(shotsDir, '03_final.png'), fullPage: true });
  } catch {}

  /* --- XHR follow-up: re-fetch promising fragments --- */
  for (const rec of xhrScan) {
    const isHtmlish = /html/.test(rec.ct || '');
    const looksFragment = XHR_FRAGMENT_CANDIDATES.some(s => (rec.url || '').includes(s));
    if (!isHtmlish && !looksFragment) continue;

    try {
      const r = await fetchText(rec.url, { headers: { 'Accept': rec.ct || 'text/html', 'X-Requested-With': 'XMLHttpRequest' }, timeout: 10000 });
      if (r.error || typeof r.text !== 'string') continue;

      const content = r.text;
      const sig = analyzeHtmlContent(content, teaserLength);

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
          id: 'xhr_refetch',
          title: `XHR refetch success (${sig.validationScore})`,
          severity: 'High',
          evidence: {
            url: rec.url,
            ct: rec.refetch.ct,
            htmlSignals: sig,
            sha256: rec.refetch.sha256,
            contentPath: contentPath.replace(targetOut + '/', '')
          }
        });
        console.log(`🔄 XHR refetch: ${sig.wordCount} words`);
      }
    } catch {}
  }

  /* ----------------- Save artifacts ----------------- */
  try { await writeJson(path.join(targetOut, 'xhr_scan.json'), xhrScan); } catch {}
  try { await writeJson(path.join(targetOut, 'header_checks.json'), headerChecks); } catch {}
  try { await writeJson(path.join(targetOut, 'json_probes.json'), jsonProbes); } catch {}
  try { await writeJson(path.join(targetOut, 'js_scan.json'), scriptUrls); } catch {}
  try { await writeJson(path.join(targetOut, 'raw_probes.json'), {
    target: CFG.url, 
    articleDom: { sel: articleDom.sel, len: articleDom.len }, 
    altViews, 
    notes: rawNotes,
    teaserLength
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
    findings,
    summary: {
      totalFindings: findings.length,
      critical: findings.filter(f => f.severity === 'Critical').length,
      high: findings.filter(f => f.severity === 'High').length,
      medium: findings.filter(f => f.severity === 'Medium').length,
      info: findings.filter(f => f.severity === 'Info').length,
      low: findings.filter(f => f.severity === 'Low').length
    }
  };
  try { await writeJson(path.join(targetOut, 'report.json'), report); } catch (e) { console.error('write report failed:', e.message); }

  /* ----------------- Console Summary ----------------- */
  console.log('\n' + '='.repeat(60));
  console.log('SCAN SUMMARY');
  console.log('='.repeat(60));

  const sevCount = findings.reduce((m, f) => (m[f.severity] = (m[f.severity] || 0) + 1, m), {});
  const sevRows = Object.entries(sevCount).sort((a,b)=>['Critical','High','Medium','Low','Info'].indexOf(a[0]) - ['Critical','High','Medium','Low','Info'].indexOf(b[0]))
    .map(([sev,c], idx)=>[idx+1, sev, c]);

  console.log('\nBy Severity:');
  console.log(table(sevRows, ['#','Severity','Count']));

  console.log('\nTop Findings (First 8):');
  const top = findings
    .filter(f => ['Critical','High'].includes(f.severity))
    .slice(0, 8)
    .map((f, i) => [i+1, f.id, short(f.title), f.severity]);
  console.log(table(top, ['#','ID','Title','Severity']));

  console.log('\n📁 Artifacts:');
  console.log(`   Directory: ${targetOut}`);
  console.log(`   Report JSON: ${path.join(targetOut, 'report.json')}`);
  console.log(`   Content files: ${fs.existsSync(contentDir) ? fs.readdirSync(contentDir).length : 0} files`);
  console.log(`   Screenshots: ${fs.existsSync(shotsDir) ? fs.readdirSync(shotsDir).length : 0} images`);

  // Generate Markdown report
  const md = [
    `# Smoke Report for ${CFG.url}`,
    '',
    `**Generated:** ${new Date().toISOString()}`,
    `**Total Findings:** ${findings.length}`,
    '',
    '## Summary by Severity',
    '',
    `| Severity | Count |`,
    `|----------|-------|`,
    ...Object.entries(sevCount).sort((a,b)=>['Critical','High','Medium','Low','Info'].indexOf(a[0]) - ['Critical','High','Medium','Low','Info'].indexOf(b[0]))
      .map(([sev,c]) => `| **${sev}** | ${c} |`),
    '',
    '## Key Findings',
    '',
    ...findings
      .filter(f => ['Critical','High'].includes(f.severity))
      .slice(0, 10)
      .map(f => {
        const contentPath = f.evidence?.contentPath ? `\n\n**Content:** ${f.evidence.contentPath}` : '';
        return `### ${f.title}\n**ID:** ${f.id} | **Severity:** ${f.severity}${contentPath}`;
      }),
    '',
    '## All Findings',
    '',
    ...findings.map(f => {
      const contentPath = f.evidence?.contentPath ? ` [${f.evidence.contentPath}]` : '';
      return `- **${f.severity}** — ${f.title} (${f.id})${contentPath}`;
    })
  ].join('\n');

  const mdPath = path.join(targetOut, 'report.md');
  try { await fs.promises.writeFile(mdPath, md, 'utf8'); } catch {}

  const successCount = findings.filter(f => ['Critical','High'].includes(f.severity)).length;
  const totalContentFiles = fs.existsSync(contentDir) ? fs.readdirSync(contentDir).filter(f => !f.includes('json')).length : 0;

  console.log('\n' + '='.repeat(60));
  console.log(`🎯 RESULT: ${successCount} successful extractions, ${totalContentFiles} content files saved`);
  if (successCount === 0) {
    console.log('No full content found. Try:');
    console.log('   • Wait for archive services to process');
    console.log('   • Use a VPN to reset IP-based metering');
    console.log('   • Check content/ directory for partial extracts');
  }
  console.log(`Full report: ${mdPath}`);
  console.log('='.repeat(60));

  console.log('\n✅ Scan complete. Remember: Use responsibly and support journalism where possible.\n');

  try { await context.close(); } catch {}
  try { await browser.close(); } catch {}
  process.exit(0);
})().catch(e => { 
  console.error('Fatal error:', e); 
  process.exit(1); 
});