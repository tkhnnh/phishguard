console.log("PhishGuard content script loaded — v2 (url-scoped)");

// --- Finding the currently-open email ---------------------------------------
// Gmail is a single-page app: it keeps old content in the DOM and reuses
// generic elements (every inbox row has a span[email]). A document-wide
// querySelector therefore returns STALE elements. Two rules keep us honest:
//   1. Scope every lookup to the open conversation container: div[role="main"].
//   2. Detect "which email" by the URL, which Gmail changes per conversation.

// The conversation pane. When you're in the inbox list (no email open) this
// still exists but won't contain a subject header (h2.hP), which we use as the
// "an email is actually open" signal.
function getOpenConversation() {
  return document.querySelector('div[role="main"]');
}

// Reads the open email into the backend's EmailIn shape. Everything is queried
// *within* the conversation pane so we never pick up inbox-list rows or a
// previously-opened thread left in the DOM.
function extractEmail() {
  const main = getOpenConversation();
  if (!main) return null;

  const subjectEl = main.querySelector("h2.hP");
  if (!subjectEl) return null; // no subject => no email open (we're in the list)

  // Sender: the message header's span carries the real address in `email`.
  const senderEl = main.querySelector("span[email]");
  // Body: the message text container.
  const bodyEl = main.querySelector("div.a3s");

  const subject = subjectEl.innerText?.trim() || "";
  const sender = senderEl?.getAttribute("email") || "";
  const body_text = bodyEl?.innerText?.trim() || "";

  const linkEls = bodyEl ? bodyEl.querySelectorAll("a[href]") : [];
  const urls = Array.from(linkEls)
    .map((a) => a.href)
    .filter((href) => href.startsWith("http"));

  return { sender, subject, body_text, urls };
}

// --- Reacting to navigation --------------------------------------------------
// We remember the URL of the email we last analyzed. When the URL changes we
// know the user opened a different email (or returned to the list).
let lastUrl = null;

function onNavigationMaybeChanged() {
  const currentUrl = location.href;
  if (currentUrl === lastUrl) return; // nothing changed since last check
  lastUrl = currentUrl;

  const email = extractEmail();

  // Back in the inbox list (or Gmail still rendering): clear any old banner.
  if (!email || !email.subject) {
    removeBanner();
    return;
  }

  // If the extension was reloaded while this old content script is still running
  // in the page, chrome.runtime is invalidated. Guard so we fail quietly instead
  // of throwing "Extension context invalidated" — a Gmail tab reload fixes it.
  if (!chrome.runtime?.id) return;

  // Immediately replace any previous banner with a pending state, so the old
  // email's verdict never lingers on the new email while analysis is in flight.
  showPending();

  try {
    chrome.runtime.sendMessage(
      { type: "ANALYZE_EMAIL", email: email },
      (response) => {
        if (chrome.runtime.lastError) return; // stale channel; ignore
        console.log("[PhishGuard] Verdict:", response);
        if (response && !response.error) {
          showBanner(response);
        }
      }
    );
  } catch (e) {
    // Context invalidated between the check and the call — safe to ignore.
  }
}

// --- Banner ------------------------------------------------------------------
function removeBanner() {
  const existing = document.getElementById("phishguard-banner");
  if (existing) existing.remove();
}

// Neutral "analyzing…" banner shown instantly while the backend is working,
// so the previous email's result is never mistaken for the current one.
function showPending() {
  const main = getOpenConversation();
  const bodyEl = main ? main.querySelector("div.a3s") : null;
  if (!bodyEl || !bodyEl.parentElement) return;

  removeBanner();
  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.className = "phishguard-banner phishguard-pending";
  banner.textContent = "PhishGuard: analyzing this email…";
  bodyEl.parentElement.insertBefore(banner, bodyEl);
}

function showBanner(result) {
  const main = getOpenConversation();
  const bodyEl = main ? main.querySelector("div.a3s") : null;
  if (!bodyEl || !bodyEl.parentElement) return;

  removeBanner(); // never stack two banners

  const level = (result.verdict || "").toLowerCase();
  const score = result.score ?? 0;

  // Rank signals worst-first so the most important reason is on top.
  const signals = (result.signals || [])
    .slice()
    .sort((a, b) => (b.weight || 0) - (a.weight || 0));

  // Cap the visible list; summarize the rest so a noisy email isn't a wall.
  const MAX_REASONS = 4;
  const shown = signals.slice(0, MAX_REASONS);
  const extra = signals.length - shown.length;

  const reasons = shown
    .map((s) => `<li class="phishguard-reason-${escapeHtml(s.severity || "info")}">${escapeHtml(s.message)}</li>`)
    .join("");
  const moreLine = extra > 0
    ? `<li class="phishguard-more">…and ${extra} more signal${extra === 1 ? "" : "s"}</li>`
    : "";

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.className = `phishguard-banner phishguard-${level}`;

  banner.innerHTML = `
    <div class="phishguard-headline">
      <span class="phishguard-badge">${escapeHtml(result.verdict || "Unknown")}</span>
      <span class="phishguard-confidence">${confidenceLabel(score)}</span>
      <span class="phishguard-score">${score}/100</span>
    </div>
    <div class="phishguard-meter"><div class="phishguard-meter-fill" style="width:${score}%"></div></div>
    ${reasons || moreLine ? `<ul class="phishguard-reasons">${reasons}${moreLine}</ul>` : `<div class="phishguard-none">No risk signals found.</div>`}
  `;

  bodyEl.parentElement.insertBefore(banner, bodyEl);
}

// A rough confidence cue derived from how far the score is from the boundaries.
function confidenceLabel(score) {
  if (score >= 85 || score < 15) return "High confidence";
  if (score >= 70 || score < 30) return "Medium confidence";
  return "Low confidence";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Poll for navigation changes. Gmail doesn't fire normal navigation events for
// its in-app routing, so polling location.href is the simplest reliable signal.
setInterval(onNavigationMaybeChanged, 1000);
