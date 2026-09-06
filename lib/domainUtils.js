// lib/domainUtils.js
// Pure utility functions for domain parsing and lookalike-domain detection.
// No DOM access here so this file can be unit-tested / reused in the
// background service worker as well as content scripts.

/**
 * Extracts the hostname from a URL string.
 */
function getHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return "";
  }
}

/**
 * Very small public-suffix-agnostic "registrable domain" extractor.
 * Not a full PSL implementation, but handles the common two-level
 * regional TLD cases (e.g. co.uk) well enough for heuristic use.
 */
function getRegistrableDomain(hostname) {
  if (!hostname) return "";
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;

  const lastTwo = parts.slice(-2).join(".");
  const knownTwoPartTlds = [
    "co.uk", "co.in", "com.au", "com.br", "com.mx", "co.jp", "com.sg",
    "co.nz", "org.uk", "gov.uk", "ac.uk", "co.za"
  ];
  const lastThree = parts.slice(-3).join(".");
  for (const tld of knownTwoPartTlds) {
    if (lastThree.endsWith("." + tld) || lastThree === tld) {
      return parts.slice(-3).join(".");
    }
  }
  return lastTwo;
}

/**
 * Classic Levenshtein edit distance between two strings.
 */
function levenshteinDistance(a, b) {
  if (a === b) return 0;
  const al = a.length, bl = b.length;
  if (al === 0) return bl;
  if (bl === 0) return al;

  let prev = new Array(bl + 1);
  let curr = new Array(bl + 1);
  for (let j = 0; j <= bl; j++) prev[j] = j;

  for (let i = 1; i <= al; i++) {
    curr[0] = i;
    for (let j = 1; j <= bl; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[bl];
}

// Homoglyph / common-substitution normalization map. Maps visually or
// keyboard-adjacent confusable characters/sequences to a canonical form
// so that e.g. "paypa1" and "paypal" normalize to the same string, and
// "rnicrosoft" (rn -> m) normalizes toward "microsoft".
// Each rule maps a whole equivalence class of confusable characters/sequences
// to one canonical form, so ambiguous glyphs (e.g. "1" can visually stand in
// for either "l" or "i") are normalized the same way on both the candidate
// and the real brand name, regardless of which one used which glyph.
const HOMOGLYPH_MAP = [
  [/[1lI]/g, "i"],  // "1" is ambiguous with both "l" and "i" - canonicalize all three
  [/0/g, "o"],
  [/3/g, "e"],
  [/4/g, "a"],
  [/[5$]/g, "s"],
  [/7/g, "t"],
  [/8/g, "b"],
  [/rn/g, "m"],
  [/vv/g, "w"],
  [/-/g, ""],
  [/_/g, ""]
];

function normalizeForComparison(str) {
  let s = str.toLowerCase();
  for (const [pattern, replacement] of HOMOGLYPH_MAP) {
    s = s.replace(pattern, replacement);
  }
  return s;
}

/**
 * Strips the TLD from a registrable domain, returning just the label,
 * e.g. "paypal.com" -> "paypal".
 */
function stripTld(domain) {
  const idx = domain.indexOf(".");
  return idx === -1 ? domain : domain.substring(0, idx);
}

/**
 * Checks a candidate hostname against the known brand list and returns
 * the closest match plus a risk assessment, or null if nothing suspicious
 * is found.
 *
 * brands: array of { name, domain }
 */
function findLookalikeMatch(hostname, brands) {
  // Raw IP hosts have no "brand label" to compare - skip to avoid noise;
  // they're still flagged separately by structuralDomainFlags().
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return null;

  const registrable = getRegistrableDomain(hostname);
  if (!registrable) return null;

  const candidateLabel = stripTld(registrable);
  const candidateNormalized = normalizeForComparison(candidateLabel);

  let best = null;

  for (const brand of brands) {
    const brandRegistrable = brand.domain.toLowerCase();

    // Exact match (or legitimate subdomain of the real brand) -> not suspicious.
    if (
      registrable === brandRegistrable ||
      hostname === brandRegistrable ||
      hostname.endsWith("." + brandRegistrable)
    ) {
      return null;
    }

    const brandLabel = stripTld(brandRegistrable);
    const brandNormalized = normalizeForComparison(brandLabel);

    // 1) Exact match only after homoglyph normalization -> strong signal
    //    e.g. paypa1 -> paypal, micr0soft -> microsoft
    if (candidateNormalized === brandNormalized && candidateLabel !== brandLabel) {
      best = {
        brand: brand.name,
        realDomain: brand.domain,
        matchedHostname: hostname,
        reason: "homoglyph",
        distance: 0,
        severity: "high"
      };
      break;
    }

    // 2) Small edit distance on the raw label (typosquatting), scaled by length.
    //    Skip brand labels that are too short (e.g. "x") to avoid noisy
    //    coincidental matches against unrelated hostnames.
    if (brandLabel.length >= 4 && Math.abs(candidateLabel.length - brandLabel.length) <= 2) {
      const dist = levenshteinDistance(candidateLabel, brandLabel);
      const threshold = brandLabel.length <= 5 ? 1 : 2;
      if (dist > 0 && dist <= threshold) {
        if (!best || dist < best.distance) {
          best = {
            brand: brand.name,
            realDomain: brand.domain,
            matchedHostname: hostname,
            reason: "typosquat",
            distance: dist,
            severity: dist === 1 ? "high" : "medium"
          };
        }
      }
    }

    // 3) Brand name used as a subdomain/prefix/suffix of an unrelated
    //    domain, e.g. "paypal-secure-login.com" or "login-paypal.verify.xyz"
    if (
      brandLabel.length >= 4 &&
      candidateNormalized !== brandNormalized &&
      candidateNormalized.includes(brandNormalized)
    ) {
      if (!best) {
        best = {
          brand: brand.name,
          realDomain: brand.domain,
          matchedHostname: hostname,
          reason: "brand-in-domain",
          distance: null,
          severity: "medium"
        };
      }
    }
  }

  return best;
}

/**
 * Flags domains using suspicious raw-IP hosts, excessive subdomain
 * nesting, or punycode (xn--) which is a common homograph-attack vector.
 */
function structuralDomainFlags(hostname) {
  const flags = [];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    flags.push({ type: "raw-ip-host", severity: "medium" });
  }
  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    flags.push({ type: "punycode-domain", severity: "medium" });
  }
  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 4) {
    flags.push({ type: "excessive-subdomains", severity: "low" });
  }
  const suspiciousKeywords = [
    "secure", "verify", "update", "confirm", "account", "signin",
    "login", "wallet", "support", "billing", "alert"
  ];
  const label = stripTld(getRegistrableDomain(hostname));
  const keywordHits = suspiciousKeywords.filter((k) => label.includes(k));
  if (keywordHits.length >= 2) {
    flags.push({ type: "suspicious-keywords", severity: "low", keywords: keywordHits });
  }
  return flags;
}

if (typeof module !== "undefined") {
  module.exports = {
    getHostname,
    getRegistrableDomain,
    levenshteinDistance,
    normalizeForComparison,
    findLookalikeMatch,
    structuralDomainFlags
  };
}
