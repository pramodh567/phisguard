const API_ENDPOINT = "http://127.0.0.1:8000/api/v1/scan";
const IGNORE_DOMAINS = ["127.0.0.1", "localhost"];
const CACHE_TTL_MS = 30 * 60 * 1000; // 30-minute persistent cache
const COOLDOWN_MS = 30 * 1000;       // 30-second deduplication lock

// Synchronous in-memory timestamp tracker
const recentScanLock = new Map();

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
  } else if (data.decision === "APP") {
    chrome.action.setBadgeText({ tabId: tabId, text: "APP" });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#3B82F6" });
  }
}

// 1. Sync badge when switching tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    chrome.action.setBadgeText({ tabId: activeInfo.tabId, text: "" });
    return;
  }

  const storage = await chrome.storage.local.get(["scan_cache"]);
  const cache = storage.scan_cache || {};
  const entry = cache[tab.url];

  if (entry && entry.expiry > Date.now()) {
    updateBadge(activeInfo.tabId, entry.data);
  } else {
    chrome.action.setBadgeText({ tabId: activeInfo.tabId, text: "" });
  }
});

// 2. Navigation Completed Listener with Synchronous Lock
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0 || !details.url || !details.url.startsWith("http")) {
    return;
  }

  const url = details.url;
  const tabId = details.tabId;
  const now = Date.now();

  // SYNCHRONOUS LOCK: Check & set BEFORE any await to prevent race conditions
  const lastScan = recentScanLock.get(url) || 0;
  if (now - lastScan < COOLDOWN_MS) {
    return;
  }
  recentScanLock.set(url, now);

  try {
    const urlObj = new URL(url);
    if (IGNORE_DOMAINS.includes(urlObj.hostname)) {
      updateBadge(tabId, { decision: "APP" });
      return;
    }
  } catch (e) {
    return;
  }

  // Check Auth & Local Storage Cache
  const storage = await chrome.storage.local.get(["pg_token", "scan_cache"]);
  if (!storage.pg_token) {
    chrome.action.setBadgeText({ tabId: tabId, text: "AUTH" });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#6B7280" });
    return;
  }

  const cache = storage.scan_cache || {};
  const entry = cache[url];

  if (entry && entry.expiry > now) {
    updateBadge(tabId, entry.data);
    return;
  }

  // Perform Scan Request
  try {
    const reqStartTime = Date.now(); // ⏱️ Start timer

    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${storage.pg_token}`
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) throw new Error("API Scan Error");

    const result = await response.json();
    
    // ⏱️ Calculate full Round Trip Time and overwrite the backend's metric
    result.latency_ms = Date.now() - reqStartTime; 

    // Persist to local cache
    cache[url] = {
      data: result,
      expiry: Date.now() + CACHE_TTL_MS
    };
    await chrome.storage.local.set({ scan_cache: cache });

    updateBadge(tabId, result);
  } catch (e) {
    chrome.action.setBadgeText({ tabId: tabId, text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#6B7280" });
  }
});