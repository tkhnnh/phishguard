console.log("PhishGuard content script loaded");

// Reads the currently-open email out of Gmail's DOM and returns an object
// shaped like the backend's EmailIn schema: { sender, subject, body_text, urls }.
//
// NOTE: Gmail's HTML is auto-generated and its class names change over time.
// These selectors work today; if extraction breaks later, this is the first
// place to update. Everything uses optional chaining (?.) and defaults so a
// missing element never throws.
function extractEmail() {
  // Subject: the <h2> Gmail marks with class "hP".
  const subjectEl = document.querySelector("h2.hP");

  // Sender: Gmail puts the real address in an `email` attribute on a <span>.
  const senderEl = document.querySelector("span[email]");

  // Body: the message text lives in a div with class "a3s".
  // Gmail can show several (quoted replies etc.); the first is the main body.
  const bodyEl = document.querySelector("div.a3s");

  const subject = subjectEl?.innerText?.trim() || "";
  const sender = senderEl?.getAttribute("email") || "";
  const body_text = bodyEl?.innerText?.trim() || "";

  // Collect every link inside the body. Array.from turns the NodeList into a
  // real array so we can map it; `a.href` gives the absolute URL.
  const linkEls = bodyEl ? bodyEl.querySelectorAll("a[href]") : [];
  const urls = Array.from(linkEls)
    .map((a) => a.href)
    // Drop Gmail's internal mailto:/anchor links so we only send real web URLs.
    .filter((href) => href.startsWith("http"));

  return { sender, subject, body_text, urls };
}

// Gmail is a single-page app: opening an email does NOT reload the page, so we
// can't just run once. Instead we poll a few times a second and act only when
// the open email changes (detected by comparing the subject).
let lastSubject = null;

function onEmailMaybeChanged() {
  const email = extractEmail();

  // Only react when an email is actually open and it's a different one than last time.
  if (!email.subject || email.subject === lastSubject) return;
  lastSubject = email.subject;

  chrome.runtime.sendMessage(
    { type: "ANALYZE_EMAIL", email: email },
    (response) => {
      console.log("[PhishGuard] Verdict:", response);
      if (response && !response.error) {
        showBanner(response);
      }
    }
  );
}

// Injects a colored risk banner at the top of the open email.
function showBanner(result) {
  // The message body lives in div.a3s; we insert the banner just above it.
  const bodyEl = document.querySelector("div.a3s");
  if (!bodyEl || !bodyEl.parentElement) return;

  // Remove any banner from a previous email so we never stack two.
  const existing = document.getElementById("phishguard-banner");
  if (existing) existing.remove();

  // verdict comes back capitalized ("Safe"/"Suspicious"/"Dangerous");
  // lowercase it to use as a CSS class for coloring.
  const level = (result.verdict || "").toLowerCase();

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.className = `phishguard-banner phishguard-${level}`;

  // Build the reason list from the signals the backend returned.
  const reasons = (result.signals || [])
    .map((s) => `<li>${escapeHtml(s.message)}</li>`)
    .join("");

  banner.innerHTML = `
    <div class="phishguard-headline">
      <span class="phishguard-badge">${escapeHtml(result.verdict || "Unknown")}</span>
      <span class="phishguard-score">Risk score: ${result.score ?? "?"}/100</span>
    </div>
    ${reasons ? `<ul class="phishguard-reasons">${reasons}</ul>` : ""}
  `;

  bodyEl.parentElement.insertBefore(banner, bodyEl);
}

// Safety: never inject raw email text as HTML (an email could contain markup).
// This turns any HTML-special characters into harmless text.
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// Check every 1.5s. (Later we'll switch to a MutationObserver, which is more
// efficient, but polling is simpler to understand and plenty for now.)
setInterval(onEmailMaybeChanged, 1500);
