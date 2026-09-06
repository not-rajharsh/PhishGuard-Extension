// popup.js

function severityRank(sev) {
  return { critical: 4, high: 3, medium: 2, low: 1 }[sev] || 0;
}

function renderState(state, hostname) {
  document.getElementById("pg-host").textContent = hostname || "\u2014";

  const scoreEl = document.getElementById("pg-score");
  const statusEl = document.getElementById("pg-status");
  const labelEl = document.getElementById("pg-status-label");
  const subEl = document.getElementById("pg-status-sub");
  const issuesEl = document.getElementById("pg-issues");

  const score = state ? state.score || 0 : 0;
  const issues = state ? state.issues || [] : [];
  const whitelisted = state ? state.whitelisted : false;

  scoreEl.textContent = score;
  statusEl.classList.remove("pg-status--safe", "pg-status--caution", "pg-status--danger");

  if (whitelisted) {
    statusEl.classList.add("pg-status--safe");
    labelEl.textContent = "Trusted by you";
    subEl.textContent = "You've marked this site as trusted.";
  } else if (score >= 70) {
    statusEl.classList.add("pg-status--danger");
    labelEl.textContent = "High risk \u2014 likely phishing";
    subEl.textContent = "Avoid entering passwords or payment details here.";
  } else if (score >= 40) {
    statusEl.classList.add("pg-status--caution");
    labelEl.textContent = "Suspicious page";
    subEl.textContent = "Some signs of a phishing or scam page were found.";
  } else {
    statusEl.classList.add("pg-status--safe");
    labelEl.textContent = "Looking safe";
    subEl.textContent = "No significant issues detected on this page.";
  }

  issuesEl.innerHTML = "";
  if (issues.length === 0) {
    const div = document.createElement("div");
    div.className = "pg-empty";
    div.textContent = whitelisted
      ? "Analysis is skipped for trusted sites."
      : "No suspicious signals found.";
    issuesEl.appendChild(div);
  } else {
    const sorted = issues.slice().sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    for (const issue of sorted) {
      const row = document.createElement("div");
      row.className = "pg-issue";
      row.innerHTML = `<span class="pg-sev pg-sev--${issue.severity}"></span><span>${escapeHtml(issue.detail)}</span>`;
      issuesEl.appendChild(row);
    }
  }
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderRecent() {
  chrome.storage.local.get(["scanHistory"], (res) => {
    const list = document.getElementById("pg-recent-list");
    list.innerHTML = "";
    const history = (res.scanHistory || []).slice(0, 6);
    if (history.length === 0) {
      const li = document.createElement("li");
      li.textContent = "Nothing flagged yet.";
      list.appendChild(li);
      return;
    }
    for (const entry of history) {
      const li = document.createElement("li");
      li.innerHTML = `<span class="pg-recent-host">${escapeHtml(entry.hostname)}</span><span>${entry.score}</span>`;
      list.appendChild(li);
    }
  });
}

function withActiveTab(callback) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) callback(tabs[0]);
  });
}

function loadCurrentState() {
  withActiveTab((tab) => {
    chrome.runtime.sendMessage({ type: "GET_TAB_STATE", tabId: tab.id }, (state) => {
      let hostname = state && state.hostname;
      if (!hostname) {
        try {
          hostname = new URL(tab.url).hostname;
        } catch (e) {
          hostname = tab.url;
        }
      }
      renderState(state, hostname);
    });
  });
}

document.getElementById("pg-rescan").addEventListener("click", () => {
  withActiveTab((tab) => {
    chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id });
    setTimeout(loadCurrentState, 600);
  });
});

document.getElementById("pg-trust").addEventListener("click", () => {
  withActiveTab((tab) => {
    try {
      const hostname = new URL(tab.url).hostname;
      chrome.runtime.sendMessage({ type: "TRUST_DOMAIN", payload: { hostname } }, () => {
        chrome.runtime.sendMessage({ type: "RESCAN_TAB", tabId: tab.id });
        setTimeout(loadCurrentState, 600);
      });
    } catch (e) {
      /* non-http URL, ignore */
    }
  });
});

loadCurrentState();
renderRecent();
