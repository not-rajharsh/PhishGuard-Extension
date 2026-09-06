# PhishGuard — Phishing & Scam Site Detector (Chrome Extension)

A Manifest V3 Chrome extension that analyzes web pages as they load and flags
signs of phishing, scam, or credential-harvesting sites — before you enter
sensitive information.

## What it detects

- **Lookalike / typosquatted domains** — e.g. `paypa1.com`, `rnicrosoft.com`,
  `g00gle.com`, `netfl1x-billing.com` — via homoglyph normalization and
  edit-distance comparison against a list of commonly-impersonated brands.
- **Brand-name-in-unrelated-domain tricks** — e.g. `login-paypal-secure.xyz`.
- **Credential-stealing forms** — password/card fields that submit to a
  different domain than the page itself, submit over plain HTTP, or are
  hidden from view.
- **Insecure connections** — pages loaded over HTTP, or HTTPS pages with
  mixed-content (HTTP) form submissions.
- **Suspicious redirect chains** — excessive redirects and cross-domain
  redirect chains before the final page loads (a common cloaking technique).
- **Dangerous downloads** — direct links to and actual downloads of `.exe`,
  `.scr`, `.bat`, `.msi`, `.jar`, `.vbs`, `.js`, `.ps1`, `.hta`, `.apk`, etc.
- **Page-level red flags** — anchor text/href domain mismatches, invisible
  full-page overlays, meta-refresh redirects, and high-pressure/urgency
  language ("your account will be suspended", "verify immediately", ...).
- **Structural domain flags** — raw-IP hosts, punycode domains, excessive
  subdomain nesting, suspicious keyword stuffing in the domain name.

Each finding is weighted by severity (`critical` / `high` / `medium` / `low`)
into a single 0–100 risk score per page.

## How it works

- **`content.js`** (+ `lib/pageAnalyzer.js`, `lib/domainUtils.js`,
  `lib/brandList.js`) runs on every page at `document_start`, re-scans on
  DOM mutations (phishing kits often inject forms after load) and on
  SPA navigation, and injects an in-page warning banner for risky pages.
- **`background.js`** is the MV3 service worker. It tracks navigation and
  redirect chains via `webNavigation`/`webRequest`, monitors `downloads`
  for dangerous file types, aggregates findings per tab, updates the
  toolbar badge (green/amber/red), and fires notifications for high-risk
  pages.
- **`popup.html`/`popup.js`** shows the current page's risk score, the
  specific issues found, a rescan button, a "trust this site" button, and
  recently flagged sites.
- **`options.html`/`options.js`** lets you manage your whitelist, toggle
  notifications/download alerts, adjust sensitivity, and review scan/
  download history.

All analysis runs **locally in the browser** — nothing is sent to a
remote server.

## Installing (Developer Mode)

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select the `phishing-detector` folder.
5. The PhishGuard icon appears in your toolbar. Click it any time to see
   the current page's risk score and findings.

## Limitations & notes

- The brand list in `lib/brandList.js` is a curated set of frequently
  impersonated brands, not exhaustive — extend it for your own use case.
- Domain-parsing uses a small heuristic (not a full Public Suffix List),
  which is good enough for common regional TLDs (`.co.uk`, `.com.au`, etc.)
  but may not cover every edge case.
- This is a **heuristic risk indicator**, not a guarantee. Always verify
  suspicious sites independently, use your browser's built-in Safe
  Browsing, and never enter credentials on a site you don't fully trust.
- `chrome.webRequest` blocking APIs are restricted in Manifest V3, so this
  extension **observes and warns** rather than silently blocking network
  requests; the in-page banner and popup are the primary intervention
  points.

## File structure

```
phishing-detector/
├── manifest.json
├── background.js          # service worker: nav/redirect/download tracking
├── content.js              # orchestrates page analysis + warning banner
├── content.css             # styling for the in-page warning banner
├── popup.html/.css/.js     # toolbar popup UI
├── options.html/.css/.js   # settings & whitelist management page
├── lib/
│   ├── brandList.js        # known brand domains for lookalike detection
│   ├── domainUtils.js       # Levenshtein distance, homoglyph normalization
│   └── pageAnalyzer.js      # DOM heuristics (forms, links, HTTPS, language)
└── icons/                  # toolbar icons
```
