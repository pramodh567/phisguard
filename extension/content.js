window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data) return;

    if (event.data.type === "PG_LOGIN_SUCCESS") {
        chrome.storage.local.set({ "pg_token": event.data.token });
    } else if (event.data.type === "PG_LOGOUT") {
        // Clear auth token AND scan cache on logout
        chrome.storage.local.remove(["pg_token", "scan_cache"]);
    }
});