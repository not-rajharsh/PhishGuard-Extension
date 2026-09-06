// lib/pageAnalyzer.js
// DOM-facing heuristics. Runs inside the page's content-script context.
// Depends on domainUtils.js and brandList.js being loaded first.

const URGENCY_PHRASES = [
  "verify your account", "account suspended", "unusual activity",
  "confirm your identity", "your account will be closed",
  "click here immediately", "act now", "limited time", "password expires",
  "unauthorized login attempt", "suspended due to", "reactivate your account",
  "update your payment", "you have been selected", "claim your reward"
];

function analyzeConnectionSecurity() {
  const issues = [];
  if (location.protocol !== "https:") {
    issues.push({
      type: "insecure-connection",
      severity: "medium",
      detail: "Page is loaded over unencrypted HTTP."
    });
  }
  // Mixed content: page is https but has http subresources / forms
  if (location.protocol === "https:") {
    const insecureForms = Array.from(document.forms).filter((f) => {
      try {
        const action = f.action ? new URL(f.action, location.href) : null;
        return action && action.protocol === "http:";
      } catch (e) {
        return false;
      }
    });
    if (insecureForms.length > 0) {
      issues.push({
        type: "mixed-content-form",
        severity: "high",
        detail: `${insecureForms.length} form(s) submit over plain HTTP from an HTTPS page.`
      });
    }
  }
  return issues;
}

function analyzeForms() {
  const issues = [];
  const forms = Array.from(document.forms);
  const pageOrigin = location.origin;
  const pageHostname = location.hostname;

  for (const form of forms) {
    const passwordFields = form.querySelectorAll('input[type="password"]');
    const cardFields = form.querySelectorAll(
      'input[autocomplete*="cc-"], input[name*="card"], input[name*="cvv"], input[name*="ccv"]'
    );
    if (passwordFields.length === 0 && cardFields.length === 0) continue;

    let actionUrl = null;
    try {
      actionUrl = form.action ? new URL(form.action, location.href) : new URL(location.href);
    } catch (e) {
      // Malformed action - flag it.
      issues.push({
        type: "malformed-form-action",
        severity: "medium",
        detail: "A credential form has an unparseable submission target."
      });
      continue;
    }

    const isCrossOrigin = actionUrl.origin !== pageOrigin;
    const actionHostname = actionUrl.hostname;
    const isCrossRegistrable =
      typeof getRegistrableDomain === "function" &&
      getRegistrableDomain(actionHostname) !== getRegistrableDomain(pageHostname);

    if (isCrossOrigin && isCrossRegistrable) {
      issues.push({
        type: "cross-origin-credential-form",
        severity: "critical",
        detail: `A form collecting ${passwordFields.length ? "a password" : "payment details"} submits to a different domain: ${actionHostname}`
      });
    }

    if (actionUrl.protocol === "http:") {
      issues.push({
        type: "credential-form-over-http",
        severity: "high",
        detail: "A login/payment form submits data over an unencrypted connection."
      });
    }

    // Hidden/invisible credential fields (used to harvest data silently).
    const style = window.getComputedStyle(form);
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") {
      issues.push({
        type: "hidden-credential-form",
        severity: "high",
        detail: "A credential-collecting form is hidden from view."
      });
    }
  }
  return issues;
}

function analyzeLinksAndRedirectTricks() {
  const issues = [];

  // Meta refresh redirects
  const metaRefresh = document.querySelector('meta[http-equiv="refresh" i]');
  if (metaRefresh) {
    issues.push({
      type: "meta-refresh-redirect",
      severity: "low",
      detail: "Page uses an automatic meta-refresh redirect."
    });
  }

  // Anchor text vs href mismatch (visually claims one domain, links to another)
  const anchors = Array.from(document.querySelectorAll("a[href]")).slice(0, 400);
  let mismatchCount = 0;
  for (const a of anchors) {
    const text = (a.innerText || "").trim();
    const domainLikeMatch = text.match(/([a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?)/i);
    if (!domainLikeMatch) continue;
    try {
      const hrefHost = new URL(a.href, location.href).hostname.toLowerCase();
      const textDomain = domainLikeMatch[1].toLowerCase();
      if (!hrefHost.endsWith(textDomain) && !textDomain.endsWith(hrefHost)) {
        mismatchCount++;
      }
    } catch (e) {
      /* ignore malformed hrefs */
    }
  }
  if (mismatchCount >= 2) {
    issues.push({
      type: "anchor-text-domain-mismatch",
      severity: "medium",
      detail: `${mismatchCount} link(s) display one domain but point to another.`
    });
  }

  // Invisible/offscreen clickable overlays (clickjacking-style tricks)
  const overlays = Array.from(document.querySelectorAll("iframe, div")).filter((el) => {
    const s = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return (
      parseFloat(s.opacity) < 0.05 &&
      rect.width > window.innerWidth * 0.5 &&
      rect.height > window.innerHeight * 0.5
    );
  });
  if (overlays.length > 0) {
    issues.push({
      type: "invisible-overlay",
      severity: "medium",
      detail: "Page contains a large, nearly-invisible overlay element."
    });
  }

  return issues;
}

function analyzeUrgencyLanguage() {
  const issues = [];
  const bodyText = (document.body ? document.body.innerText : "").toLowerCase();
  const hits = URGENCY_PHRASES.filter((p) => bodyText.includes(p));
  if (hits.length >= 2) {
    issues.push({
      type: "urgency-language",
      severity: "low",
      detail: `Page uses high-pressure phrasing (${hits.slice(0, 3).join(", ")}).`
    });
  }
  return issues;
}

function analyzeDownloadLinks() {
  const issues = [];
  const dangerousExt = /\.(exe|scr|bat|cmd|msi|jar|vbs|js|ps1|lnk|hta|apk)(\?.*)?$/i;
  const links = Array.from(document.querySelectorAll("a[href]"));
  const found = new Set();
  for (const a of links) {
    if (dangerousExt.test(a.href)) {
      const m = a.href.match(dangerousExt);
      found.add(m[1].toLowerCase());
    }
  }
  if (found.size > 0) {
    issues.push({
      type: "executable-download-link",
      severity: "high",
      detail: `Page links directly to executable file type(s): ${Array.from(found).join(", ")}`
    });
  }
  return issues;
}

/**
 * Runs the full heuristic suite and returns a combined issue list plus
 * a numeric risk score (0-100).
 */
function runFullPageAnalysis() {
  const hostname = location.hostname.toLowerCase();
  const lookalike =
    typeof findLookalikeMatch === "function" ? findLookalikeMatch(hostname, KNOWN_BRANDS) : null;
  const structuralFlags =
    typeof structuralDomainFlags === "function" ? structuralDomainFlags(hostname) : [];

  const issues = [
    ...analyzeConnectionSecurity(),
    ...analyzeForms(),
    ...analyzeLinksAndRedirectTricks(),
    ...analyzeUrgencyLanguage(),
    ...analyzeDownloadLinks()
  ];

  if (lookalike) {
    issues.unshift({
      type: "lookalike-domain",
      severity: lookalike.severity,
      detail: `This domain closely resembles ${lookalike.brand} (${lookalike.realDomain}) but is not the real site.`,
      meta: lookalike
    });
  }

  for (const flag of structuralFlags) {
    issues.push({
      type: flag.type,
      severity: flag.severity,
      detail:
        flag.type === "raw-ip-host"
          ? "Site is addressed by raw IP instead of a domain name."
          : flag.type === "punycode-domain"
          ? "Domain uses punycode encoding, sometimes used to spoof lookalike characters."
          : flag.type === "excessive-subdomains"
          ? "Unusually deep subdomain chain."
          : `Domain name contains suspicious keywords: ${(flag.keywords || []).join(", ")}`
    });
  }

  const weight = { critical: 40, high: 25, medium: 12, low: 5 };
  let score = 0;
  for (const issue of issues) score += weight[issue.severity] || 5;
  score = Math.min(100, score);

  return { hostname, url: location.href, issues, score, timestamp: Date.now() };
}

if (typeof module !== "undefined") {
  module.exports = { runFullPageAnalysis };
}
