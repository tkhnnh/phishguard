console.log("PhishGuard background loaded");

// Live backend (Render). For local development, swap to "http://localhost:8000/analyze".
const BACKEND_URL = "https://phishguard-klvp.onrender.com/analyze";

// The background service worker is the extension's privileged "hub". Content
// scripts (which run inside Gmail) send it messages; it makes the network call
// to our backend and sends the result back.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_EMAIL") {
    // POST the extracted email to the backend's /analyze endpoint.
    fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message.email), // turn the JS object into JSON text
    })
      .then((res) => res.json()) // parse the JSON response into an object
      .then((result) => sendResponse(result)) // send it back to content.js
      .catch((err) => {
        console.error("[PhishGuard] Backend call failed:", err);
        sendResponse({ error: true });
      });

    // CRITICAL: fetch is async, so we must return true to tell Chrome
    // "the reply is coming later" — otherwise the message channel closes
    // before sendResponse runs and content.js never hears back.
    return true;
  }
});
