// Popup dashboard logic. Reads/writes settings + stats in chrome.storage.local,
// which the content script also uses, so the two stay in sync.

const BACKEND_HEALTH_URL = "https://phishguard-klvp.onrender.com/docs";

const els = {
  toggle: document.getElementById("pg-toggle"),
  statusText: document.getElementById("pg-status-text"),
  scanned: document.getElementById("pg-scanned"),
  flagged: document.getElementById("pg-flagged"),
  last: document.getElementById("pg-last"),
  backend: document.getElementById("pg-backend"),
  backendDot: document.getElementById("pg-backend-dot"),
  notify: document.getElementById("pg-notify-toggle"),
};

const DEFAULTS = {
  pg_enabled: true,
  pg_notify: true,
  pg_stats: { scanned: 0, flagged: 0 },
  pg_last: null,
};

function render(state) {
  // Protection toggle
  els.toggle.checked = state.pg_enabled;
  els.statusText.textContent = state.pg_enabled ? "On" : "Off";
  document.body.classList.toggle("pg-off", !state.pg_enabled);

  // Notifications
  els.notify.checked = state.pg_notify;

  // Stats
  els.scanned.textContent = state.pg_stats.scanned;
  els.flagged.textContent = state.pg_stats.flagged;

  // Last email
  const last = state.pg_last;
  if (!last) {
    els.last.textContent = "No email analyzed yet";
    els.last.className = "pg-last pg-empty";
  } else {
    const v = (last.verdict || "Unknown").toLowerCase();
    els.last.className = "pg-last";
    els.last.innerHTML =
      `<div class="pg-verdict pg-v-${v}">${last.verdict} · ${last.score}/100</div>` +
      `<div class="pg-sender">${last.sender || "(unknown sender)"}</div>`;
  }
}

// Load state and render
chrome.storage.local.get(DEFAULTS, (state) => render(state));

// Toggle protection
els.toggle.addEventListener("change", () => {
  chrome.storage.local.set({ pg_enabled: els.toggle.checked });
  els.statusText.textContent = els.toggle.checked ? "On" : "Off";
  document.body.classList.toggle("pg-off", !els.toggle.checked);
});

// Toggle notifications
els.notify.addEventListener("change", () => {
  chrome.storage.local.set({ pg_notify: els.notify.checked });
});

// Live-update stats/last while the popup is open
chrome.storage.onChanged.addListener((changes) => {
  chrome.storage.local.get(DEFAULTS, (state) => render(state));
});

// Backend health check
fetch(BACKEND_HEALTH_URL, { method: "HEAD" })
  .then((r) => {
    const ok = r.ok || r.status === 405; // HEAD may be 405 but server is up
    els.backend.textContent = ok ? "Connected" : "Unreachable";
    els.backendDot.className = "pg-dot " + (ok ? "pg-dot-ok" : "pg-dot-down");
  })
  .catch(() => {
    els.backend.textContent = "Unreachable";
    els.backendDot.className = "pg-dot pg-dot-down";
  });
