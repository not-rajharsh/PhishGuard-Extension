// content.js
// Orchestrates page analysis, talks to the background service worker,
// and injects an in-page warning banner for high-risk pages.

(function () {
  let lastScore = -1;
  let bannerInjected = false;
  let debounceTimer = null;

  function isWhitelisted(hostname, whitelist) {
    return whitelist.some((w) => hostname === w || hostname.endsWith("." + w));
  }

  function runAnalysisAndReport() {
    chrome.storage.local.get(["whitelist"], (res) => {
      const whitelist = res.whitelist || [];
      const hostname = location.hostname.toLowerCase();

      if (isWhitelisted(hostname, whitelist)) {
        chrome.runtime.sendMessage({
          type: "PAGE_ANALYSIS_RESULT",
          payload: { hostname, url: location.href, issues: [], score: 0, whitelisted: true }
        });
        return;
      }

      const result = runFullPageAnalysis();
      chrome.runtime.sendMessage({ type: "PAGE_ANALYSIS_RESULT", payload: result });

      if (result.score !== lastScore) {
        lastScore = result.score;
        if (result.score >= 40) {
          showWarningBanner(result);
        } else {
          removeWarningBanner();
        }
      }
    });
  }

  function scheduleAnalysis(delay = 300) {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runAnalysisAndReport, delay);
  }

  function severityLabel(score) {
    if (score >= 70) return { label: "Dangerous", color: "#c0152f" };
    if (score >= 40) return { label: "Suspicious", color: "#d97706" };
    return { label: "Caution", color: "#d97706" };
  }

  function showWarningBanner(result) {
    if (document.getElementById("__phishguard_banner__")) {
      updateBannerText(result);
      return;
    }
    const { label, color } = severityLabel(result.score);

    const banner = document.createElement("div");
    banner.id = "__phishguard_banner__";
    banner.setAttribute("data-phishguard", "true");

    const topIssues = result.issues
      .slice()
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
      .slice(0, 2)
      .map((i) => i.detail);

    banner.innerHTML = `
      <div class="pg-banner-inner" style="border-left-color:${color}">
        <div class="pg-banner-icon">\u26A0\uFE0F</div>
        <div class="pg-banner-text">
          <strong>PhishGuard: ${label} site detected</strong>
          <span class="pg-banner-detail">${escapeHtml(topIssues.join(" \u2022 "))}</span>
        </div>
        <div class="pg-banner-actions">
          <button id="__pg_details__">Details</button>
          <button id="__pg_trust__">I trust this site</button>
          <button id="__pg_dismiss__" aria-label="Dismiss">\u2715</button>
        </div>
      </div>
    `;
    document.documentElement.appendChild(banner);
    bannerInjected = true;

    document.getElementById("__pg_dismiss__").addEventListener("click", removeWarningBanner);
    document.getElementById("__pg_trust__").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "TRUST_DOMAIN", payload: { hostname: location.hostname } });
      removeWarningBanner();
    });
    document.getElementById("__pg_details__").addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "OPEN_POPUP_DETAILS" });
    });
  }

  function updateBannerText(result) {
    const el = document.getElementById("__phishguard_banner__");
    if (!el) return;
    const { label, color } = severityLabel(result.score);
    const strong = el.querySelector("strong");
    const detail = el.querySelector(".pg-banner-detail");
    const inner = el.querySelector(".pg-banner-inner");
    if (strong) strong.textContent = `PhishGuard: ${label} site detected`;
    if (inner) inner.style.borderLeftColor = color;
    if (detail) {
      const topIssues = result.issues
        .slice()
        .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
        .slice(0, 2)
        .map((i) => i.detail);
      detail.textContent = topIssues.join(" \u2022 ");
    }
  }

  function severityRank(sev) {
    return { critical: 4, high: 3, medium: 2, low: 1 }[sev] || 0;
  }

  function removeWarningBanner() {
    const el = document.getElementById("__phishguard_banner__");
    if (el) el.remove();
    bannerInjected = false;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // Listen for background asking for a fresh scan (e.g. from popup "rescan").
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "RESCAN_REQUEST") {
      lastScore = -1;
      runAnalysisAndReport();
      sendResponse({ ok: true });
    }
  });

  // Initial scan once DOM is interactive, then watch for dynamic changes
  // (phishing kits frequently inject forms after page load).
  function init() {
    scheduleAnalysis(50);

    const observer = new MutationObserver((mutations) => {
      const relevant = mutations.some((m) =>
        Array.from(m.addedNodes).some(
          (n) =>
            n.nodeType === 1 &&
            (n.tagName === "FORM" ||
              n.tagName === "IFRAME" ||
              (n.querySelector && n.querySelector("form,input[type=password]")))
        )
      );
      if (relevant) scheduleAnalysis(500);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    // Re-check on visibility change (SPA route changes, tab refocus).
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") scheduleAnalysis(500);
    });

    // Basic SPA navigation detection (pushState/replaceState/hashchange).
    let lastUrl = location.href;
    setInterval(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        lastScore = -1;
        scheduleAnalysis(300);
      }
    }, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
