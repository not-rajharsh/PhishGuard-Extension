// background.js (Manifest V3 service worker)
// Tracks navigation/redirect chains per tab, monitors downloads for
// dangerous file types, aggregates content-script findings, and drives
// the toolbar badge + notifications.

const DANGEROUS_DOWNLOAD_EXT = [
  "exe", "scr", "bat", "cmd", "msi", "jar", "vbs", "js", "ps1", "lnk",
  "hta", "apk", "com", "pif", "gadget", "wsf"
];

// In-memory per-tab state (rebuilt as needed; also mirrored to storage
// for the popup to read).
const tabState = new Map(); // tabId -> { redirects: [], score, issues, hostname, url }

function getState(tabId) {
  if (!tabState.has(tabId)) {
    tabState.set(tabId, { redirects: [], score: 0, issues: [], hostname: "", url: "", downloadFlags: [] });
  }
  return tabState.get(tabId);
}

function setBadge(tabId, score) {
  let text = "";
  let color = "#22c55e"; // green
  if (score >= 70) {
    text = "!!";
    color = "#dc2626"; // red
  } else if (score >= 40) {
    text = "!";
    color = "#d97706"; // amber
  } else if (score > 0) {
    text = "";
    color = "#22c55e";
  }
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function notifyIfSevere(tabId, state) {
  if (state.score >= 70 && !state._notified) {
    state._notified = true;
    chrome.notifications.create(`pg-${tabId}-${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "PhishGuard: Dangerous site blocked from your trust",
      message: `${state.hostname} shows strong signs of phishing. Avoid entering passwords or payment info.`,
      priority: 2
    });
  }
}

// ---------- Redirect chain tracking ----------

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // top-level frame only
  const state = getState(details.tabId);
  state.redirects = [{ url: details.url, ts: Date.now() }];
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const state = getState(details.tabId);
  const transition = details.transitionQualifiers || [];
  if (transition.includes("server_redirect") || transition.includes("client_redirect")) {
    state.redirects.push({ url: details.url, ts: Date.now() });
  } else if (state.redirects.length === 0) {
    state.redirects.push({ url: details.url, ts: Date.now() });
  }

  if (state.redirects.length >= 4) {
    state.issues = state.issues.filter((i) => i.type !== "excessive-redirects");
    state.issues.push({
      type: "excessive-redirects",
      severity: "medium",
      detail: `Page went through ${state.redirects.length} redirects before loading.`
    });
    recomputeScore(details.tabId);
  }
});

// Cross-domain redirect chains ending far from where they started is a
// classic cloaking technique (ad-network -> phishing kit).
chrome.webNavigation.onBeforeRedirect ? null : null; // (webNavigation has no onBeforeRedirect; using webRequest below)

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type !== "main_frame") return;
    const state = getState(details.tabId);
    try {
      const fromHost = new URL(details.url).hostname;
      const toHost = new URL(details.redirectUrl).hostname;
      if (fromHost !== toHost) {
        state.crossDomainRedirects = (state.crossDomainRedirects || 0) + 1;
      }
    } catch (e) {
      /* ignore */
    }
  },
  { urls: ["<all_urls>"] }
);

// ---------- Download monitoring ----------

chrome.downloads.onCreated.addListener((item) => {
  const filename = (item.filename || item.url || "").toLowerCase();
  const ext = (filename.split(".").pop() || "").split("?")[0];

  if (DANGEROUS_DOWNLOAD_EXT.includes(ext)) {
    chrome.storage.local.get(["settings"], (res) => {
      const settings = res.settings || {};
      if (settings.downloadAlerts === false) return;

      chrome.notifications.create(`pg-dl-${item.id}`, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "PhishGuard: Potentially dangerous download",
        message: `"${item.filename ? item.filename.split(/[\\/]/).pop() : item.url}" is an executable file type (.${ext}). Only run it if you fully trust the source.`,
        priority: 2
      });

      chrome.storage.local.get(["downloadHistory"], (res2) => {
        const history = res2.downloadHistory || [];
        history.unshift({
          url: item.url,
          filename: item.filename,
          ext,
          time: Date.now(),
          referrer: item.referrer || ""
        });
        chrome.storage.local.set({ downloadHistory: history.slice(0, 50) });
      });
    });
  }
});

// ---------- Message handling from content scripts / popup ----------

function recomputeScore(tabId) {
  const state = getState(tabId);
  const weight = { critical: 40, high: 25, medium: 12, low: 5 };
  let score = 0;
  for (const issue of state.issues) score += weight[issue.severity] || 5;
  state.score = Math.min(100, score);
  setBadge(tabId, state.score);
  notifyIfSevere(tabId, state);
  persistState(tabId, state);
}

function persistState(tabId, state) {
  chrome.storage.session
    ? chrome.storage.session.set({ [`tab_${tabId}`]: state })
    : chrome.storage.local.set({ [`tab_${tabId}`]: state });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  if (msg.type === "PAGE_ANALYSIS_RESULT" && tabId !== null) {
    const state = getState(tabId);
    state.hostname = msg.payload.hostname;
    state.url = msg.payload.url;
    state.whitelisted = !!msg.payload.whitelisted;

    // Merge content-script issues with any nav-level issues (e.g. redirects)
    const navIssues = state.issues.filter(
      (i) => i.type === "excessive-redirects"
    );
    state.issues = msg.payload.whitelisted ? [] : [...msg.payload.issues, ...navIssues];
    state.score = msg.payload.whitelisted ? 0 : msg.payload.score;
    state._notified = state.score < 70 ? false : state._notified;

    // Fold in cross-domain redirect signal.
    if (!msg.payload.whitelisted && state.crossDomainRedirects >= 2) {
      state.issues.push({
        type: "cross-domain-redirect-chain",
        severity: "medium",
        detail: `Landed here after ${state.crossDomainRedirects} cross-domain redirects.`
      });
    }

    recomputeScore(tabId);

    // Log flagged sites to history for the popup / options review.
    if (state.score >= 40) {
      chrome.storage.local.get(["scanHistory"], (res) => {
        const history = res.scanHistory || [];
        history.unshift({
          hostname: state.hostname,
          url: state.url,
          score: state.score,
          time: Date.now(),
          topIssue: state.issues[0] ? state.issues[0].detail : ""
        });
        chrome.storage.local.set({ scanHistory: history.slice(0, 100) });
      });
    }
    sendResponse({ ok: true });
  }

  if (msg.type === "TRUST_DOMAIN") {
    chrome.storage.local.get(["whitelist"], (res) => {
      const whitelist = res.whitelist || [];
      if (!whitelist.includes(msg.payload.hostname)) {
        whitelist.push(msg.payload.hostname);
        chrome.storage.local.set({ whitelist });
      }
    });
  }

  if (msg.type === "OPEN_POPUP_DETAILS") {
    // Popups can't be opened programmatically; badge + title nudge instead.
    if (tabId !== null) {
      chrome.action.setTitle({ tabId, title: "PhishGuard \u2014 click for details" });
    }
  }

  if (msg.type === "GET_TAB_STATE") {
    const id = msg.tabId;
    sendResponse(getState(id));
    return true;
  }

  if (msg.type === "RESCAN_TAB") {
    chrome.tabs.sendMessage(msg.tabId, { type: "RESCAN_REQUEST" }, () => {
      void chrome.runtime.lastError; // swallow "no receiver" errors
    });
  }

  return true;
});

// Clean up state when tabs close.
chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
  chrome.storage.local.remove(`tab_${tabId}`);
});

// Reset per-navigation state on new top-level navigations so stale
// issues don't linger across page loads within the same tab.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const state = getState(details.tabId);
  if (state.url && state.url !== details.url) {
    state.issues = state.issues.filter((i) => i.type === "excessive-redirects");
    state.crossDomainRedirects = 0;
  }
});

chrome.runtime.onInstalled.addListener((details) => {
  chrome.storage.local.get(["whitelist", "settings"], (res) => {
    if (!res.whitelist) chrome.storage.local.set({ whitelist: [] });
    if (!res.settings) {
      chrome.storage.local.set({
        settings: { downloadAlerts: true, notifyOnHighRisk: true, sensitivity: "normal" }
      });
    }
  });
  if (details.reason === "install") {
    chrome.notifications.create("pg-welcome", {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "PhishGuard installed",
      message: "PhishGuard is now watching for phishing sites, lookalike domains, and risky downloads.",
      priority: 0
    });
  }
});
