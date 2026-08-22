const API_ENDPOINT = "http://127.0.0.1:8000/api/v1/scan";
const IGNORE_DOMAINS = ["127.0.0.1", "localhost"];
const CACHE_TTL_MS = 30 * 60 * 1000;

document.addEventListener("DOMContentLoaded", async () => {
  const storage = await chrome.storage.local.get(["pg_token", "scan_cache"]);
  
  // 1. Auth Guard
  if (!storage.pg_token) {
    document.getElementById("auth-screen").style.display = "flex";
    document.getElementById("app-screen").style.display = "none";
    document.getElementById("ext-login-btn").addEventListener("click", () => {
      chrome.tabs.create({ url: "http://127.0.0.1:8000/login" });
    });
    return;
  }

  document.getElementById("auth-screen").style.display = "none";
  document.getElementById("app-screen").style.display = "block";

  document.getElementById("dashboard-btn")?.addEventListener("click", () => {
    chrome.tabs.create({ url: "http://127.0.0.1:8000/dashboard" });
  });

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    document.getElementById("verdict-tag").textContent = "N/A";
    document.getElementById("target-url").textContent = tab?.url || "Non-web page";
    return;
  }

  const urlObj = new URL(tab.url);
  if (IGNORE_DOMAINS.includes(urlObj.hostname)) {
    renderSystemSafe();
    return;
  }

  // 2. Check TTL Cache
  const cache = storage.scan_cache || {};
  const entry = cache[tab.url];
  const now = Date.now();

  if (entry && entry.expiry > now) {
    renderUI(tab.id, entry.data);
  } else {
    await performScan(tab, storage.pg_token, false);
  }

  // 3. Re-scan button forces a cache bypass
  document.getElementById("rescan-btn").addEventListener("click", async () => {
    const freshStorage = await chrome.storage.local.get("pg_token");
    await performScan(tab, freshStorage.pg_token, true);
  });
});

async function performScan(tab, token, forceFresh = false) {
  const verdictEl = document.getElementById("verdict-tag");
  verdictEl.textContent = "SCANNING...";
  verdictEl.className = "tag safe";

  try {
    const reqStartTime = Date.now(); // ⏱️ Start timer

    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({ url: tab.url })
    });

    if (!response.ok) throw new Error("API error");

    const result = await response.json();
    
    // ⏱️ Calculate full Round Trip Time and overwrite the backend's metric
    result.latency_ms = Date.now() - reqStartTime;

    // Update persistent cache
    const storage = await chrome.storage.local.get("scan_cache");
    const cache = storage.scan_cache || {};
    cache[tab.url] = {
      data: result,
      expiry: Date.now() + CACHE_TTL_MS
    };
    await chrome.storage.local.set({ scan_cache: cache });

    renderUI(tab.id, result);
  } catch (e) {
    verdictEl.textContent = "API OFFLINE";
    verdictEl.className = "tag malicious";
    document.getElementById("backend-status").className = "status-dot offline";
    chrome.action.setBadgeText({ tabId: tab.id, text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: "#6B7280" });
  }
}

function renderSystemSafe() {
  const verdictEl = document.getElementById("verdict-tag");
  verdictEl.textContent = "APP";
  verdictEl.style.backgroundColor = "#3B82F6";
  verdictEl.style.color = "#ffffff";
  document.getElementById("risk-score").textContent = "0%";
  document.getElementById("latency-tag").textContent = "0 ms";
  document.getElementById("tier-used").textContent = "PhishGuard Internal";
  document.getElementById("target-url").textContent = "Dashboard UI";
  document.getElementById("sig-abnormal").textContent = "N/A";
  document.getElementById("sig-brand").textContent = "N/A";
  document.getElementById("sig-entropy").textContent = "N/A";
}

function renderUI(tabId, data) {
  const verdictEl = document.getElementById("verdict-tag");
  verdictEl.textContent = data.decision;
  verdictEl.className = `tag ${data.decision.toLowerCase()}`;
  verdictEl.style.backgroundColor = "";

  document.getElementById("risk-score").textContent = `${data.risk_score}%`;
  document.getElementById("latency-tag").textContent = `${data.latency_ms} ms`;
  document.getElementById("tier-used").textContent = data.tier_executed;
  document.getElementById("target-url").textContent = data.url;

  document.getElementById("sig-abnormal").textContent = data.features_breakdown.abnormal_url ? "Yes" : "No";
  document.getElementById("sig-brand").textContent = data.features_breakdown.exact_brand_spoof ? "Spoofed" : "None";
  document.getElementById("sig-entropy").textContent = data.features_breakdown.entropy || "0.0";

  updateBadge(tabId, data);
}

function updateBadge(tabId, data) {
  if (!tabId || !data) return;
  if (data.decision === "SAFE") {
    chrome.action.setBadgeText({ tabId: tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#10B981" });
  } else if (data.decision === "SUSPICIOUS") {
    chrome.action.setBadgeText({ tabId: tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#F59E0B" });
  } else if (data.decision === "MALICIOUS") {
    chrome.action.setBadgeText({ tabId: tabId, text: "RISK" });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#EF4444" });
  }
}