// options.js

function loadSettings() {
  chrome.storage.local.get(["settings"], (res) => {
    const s = res.settings || { notifyOnHighRisk: true, downloadAlerts: true, sensitivity: "normal" };
    document.getElementById("notifyHighRisk").checked = s.notifyOnHighRisk !== false;
    document.getElementById("downloadAlerts").checked = s.downloadAlerts !== false;
    document.getElementById("sensitivity").value = s.sensitivity || "normal";
  });
}

function saveSettings() {
  const settings = {
    notifyOnHighRisk: document.getElementById("notifyHighRisk").checked,
    downloadAlerts: document.getElementById("downloadAlerts").checked,
    sensitivity: document.getElementById("sensitivity").value
  };
  chrome.storage.local.set({ settings });
}

["notifyHighRisk", "downloadAlerts", "sensitivity"].forEach((id) => {
  document.getElementById(id).addEventListener("change", saveSettings);
});

function renderWhitelist() {
  chrome.storage.local.get(["whitelist"], (res) => {
    const list = document.getElementById("whitelistList");
    list.innerHTML = "";
    const whitelist = res.whitelist || [];
    if (whitelist.length === 0) {
      list.innerHTML = '<li class="opt-empty">No trusted sites added yet.</li>';
      return;
    }
    whitelist.forEach((domain) => {
      const li = document.createElement("li");
      li.innerHTML = `<span>${escapeHtml(domain)}</span><button data-domain="${escapeHtml(domain)}">Remove</button>`;
      list.appendChild(li);
    });
    list.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        chrome.storage.local.get(["whitelist"], (res2) => {
          const updated = (res2.whitelist || []).filter((d) => d !== btn.dataset.domain);
          chrome.storage.local.set({ whitelist: updated }, renderWhitelist);
        });
      });
    });
  });
}

document.getElementById("addWhitelist").addEventListener("click", () => {
  const input = document.getElementById("whitelistInput");
  const raw = input.value.trim().toLowerCase();
  if (!raw) return;
  let domain = raw;
  try {
    domain = raw.includes("://") ? new URL(raw).hostname : raw.replace(/\/.*$/, "");
  } catch (e) {
    /* keep raw */
  }
  chrome.storage.local.get(["whitelist"], (res) => {
    const whitelist = res.whitelist || [];
    if (!whitelist.includes(domain)) whitelist.push(domain);
    chrome.storage.local.set({ whitelist }, () => {
      input.value = "";
      renderWhitelist();
    });
  });
});

function renderHistory() {
  chrome.storage.local.get(["scanHistory"], (res) => {
    const list = document.getElementById("historyList");
    list.innerHTML = "";
    const history = res.scanHistory || [];
    if (history.length === 0) {
      list.innerHTML = '<li class="opt-empty">Nothing flagged yet.</li>';
      return;
    }
    history.forEach((entry) => {
      const li = document.createElement("li");
      const date = new Date(entry.time).toLocaleString();
      li.innerHTML = `<span>${escapeHtml(entry.hostname)} <span class="opt-meta">(score ${entry.score})</span></span><span class="opt-meta">${date}</span>`;
      list.appendChild(li);
    });
  });
}

document.getElementById("clearHistory").addEventListener("click", () => {
  chrome.storage.local.set({ scanHistory: [] }, renderHistory);
});

function renderDownloads() {
  chrome.storage.local.get(["downloadHistory"], (res) => {
    const list = document.getElementById("downloadList");
    list.innerHTML = "";
    const history = res.downloadHistory || [];
    if (history.length === 0) {
      list.innerHTML = '<li class="opt-empty">No suspicious downloads recorded.</li>';
      return;
    }
    history.forEach((entry) => {
      const li = document.createElement("li");
      const name = entry.filename ? entry.filename.split(/[\\/]/).pop() : entry.url;
      const date = new Date(entry.time).toLocaleString();
      li.innerHTML = `<span>${escapeHtml(name)} <span class="opt-meta">(.${entry.ext})</span></span><span class="opt-meta">${date}</span>`;
      list.appendChild(li);
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

loadSettings();
renderWhitelist();
renderHistory();
renderDownloads();
