// ============================================
// PromptGuard — content.js
// Intercepts prompts on ChatGPT / Gemini / Copilot / Claude
// Always sends userId from storage — never anonymous
// ============================================

function isContextValid() {
  return typeof chrome !== "undefined" && !!chrome.runtime && !!chrome.runtime.id;
}

let interceptEnabled = true;

function detectTool() {
  const h = window.location.hostname;
  if (h.includes("openai") || h.includes("chatgpt")) return "ChatGPT";
  if (h.includes("gemini")) return "Gemini";
  if (h.includes("copilot")) return "Copilot";
  if (h.includes("claude")) return "Claude";
  if (h.includes("perplexity")) return "Perplexity";
  if (h.includes("deepseek")) return "DeepSeek";
  if (h.includes("grok") || h.includes("x.com")) return "Grok";
  return "Unknown";
}

async function detectBrowser() {
  const ua = navigator.userAgent;
  // Brave: must check first — uses Chrome UA string
  try {
    if (navigator.brave && typeof navigator.brave.isBrave === "function") {
      const isBrave = await navigator.brave.isBrave();
      if (isBrave) return "Brave";
    }
  } catch (_) { }
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("OPR/") || ua.includes("Opera")) return "Opera";
  if (ua.includes("Firefox/")) return "Firefox";
  if (ua.includes("Safari/") && !ua.includes("Chrome")) return "Safari";
  if (ua.includes("Chrome/")) return "Chrome";
  return "Unknown";
}

async function getSettings() {
  return new Promise((resolve) => {
    if (!isContextValid()) {
      return resolve({
        userId: "anonymous-user", subUser: "anonymous-sub",
        apiUrl: "http://localhost:8080", enabled: true
      });
    }
    chrome.storage.sync.get(["userId", "subUser", "apiUrl", "enabled"], (data) => {
      // Catch invalidated context in callback
      if (chrome.runtime.lastError) {
        return resolve({
          userId: "anonymous-user", subUser: "anonymous-sub",
          apiUrl: "http://localhost:8080", enabled: true
        });
      }
      resolve({
        userId: (data.userId && data.userId.trim()) ? data.userId.trim() : "anonymous-user",
        subUser: (data.subUser && data.subUser.trim()) ? data.subUser.trim() : "anonymous-sub",
        apiUrl: (data.apiUrl && data.apiUrl.trim()) ? data.apiUrl.trim() : "http://localhost:8080",
        enabled: data.enabled !== false,
      });
    });
  });
}

function showToast(message, type) {
  const old = document.getElementById("pg-toast");
  if (old) old.remove();

  const styles = {
    critical: { bg: "#991b1b", border: "#f87171", icon: "🚨" },
    block: { bg: "#dc2626", border: "#ef4444", icon: "🚫" },
    redact: { bg: "#7c3aed", border: "#a78bfa", icon: "✏️" },
    alert: { bg: "#d97706", border: "#fbbf24", icon: "⚠️" },
    allow: { bg: "#16a34a", border: "#4ade80", icon: "✅" },
  };
  const s = styles[type] || styles.allow;

  if (!document.getElementById("pg-style")) {
    const el = document.createElement("style");
    el.id = "pg-style";
    el.textContent = `@keyframes pgIn { from{transform:translateX(120%);opacity:0} to{transform:translateX(0);opacity:1} }`;
    document.head.appendChild(el);
  }

  const toast = document.createElement("div");
  toast.id = "pg-toast";
  toast.style.cssText = `
    position:fixed;top:20px;right:20px;z-index:2147483647;
    background:${s.bg};border:2px solid ${s.border};color:#fff;
    padding:14px 20px;border-radius:12px;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    font-size:14px;font-weight:600;max-width:380px;
    box-shadow:0 8px 30px rgba(0,0,0,.5);animation:pgIn .3s ease;
    line-height:1.5;`;
  toast.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:10px">
      <span style="font-size:22px;line-height:1">${s.icon}</span>
      <div style="flex:1">
        <div style="font-size:11px;font-weight:800;text-transform:uppercase;
                    letter-spacing:1.5px;margin-bottom:5px;opacity:.85">PromptGuard</div>
        <div style="font-size:13px">${message}</div>
      </div>
      <span id="pg-close" style="cursor:pointer;font-size:20px;opacity:.7;margin-left:6px">×</span>
    </div>`;
  document.body.appendChild(toast);
  document.getElementById("pg-close").addEventListener("click", () => toast.remove());
  setTimeout(() => { if (toast.parentNode) toast.remove(); }, 6000);
}

async function checkPrompt(promptText, submitFn, onDone) {
  if (!isContextValid()) {
    alert("PromptGuard extension was updated or reloaded.\nPlease refresh this page to continue using AI tools.");
    if (onDone) onDone();
    return; // Block prompt to prevent anonymous/untracked data
  }
  chrome.storage.sync.get(["enabled"], async (data) => {
    if (data.enabled === false) { submitFn(promptText); if (onDone) onDone(); return; }

    // Always call background.js to fetch config/API
    chrome.runtime.sendMessage(
      { type: "PROCESS_PROMPT", prompt: promptText, tool: detectTool(), browserName: await detectBrowser() },
      (result) => {
        // ── Always unlock interceptor after ANY response (incl. BLOCK) ──
        // FIX: Previously the unlock lived inside submitFn — so BLOCK (which
        // never calls submitFn) left interceptEnabled=false permanently,
        // causing all subsequent prompts to bypass the backend entirely.
        if (onDone) setTimeout(onDone, 1000);

        if (chrome.runtime.lastError || !result) {
          submitFn(promptText);
          return;
        }

        if (result.action === "BLOCK") {
          showToast("Prompt BLOCKED! " + result.reason, "block");
          // ✅ No submitFn — prompt is intentionally stopped. onDone still fires above.
        } else if (result.action === "REDACT") {
          showToast("Sensitive data removed. " + result.reason, "redact");
          submitFn(result.redactedPrompt || promptText);
        } else if (result.action === "ALERT" || result.action === "CRITICAL") {
          showToast("Prompt CRITICAL! " + result.reason, "alert");
          submitFn(promptText);
        } else {
          showToast("🛡️ Prompt SECURE. No risks detected.", "allow");
          submitFn(promptText);
        }
      }
    );
  });
}

function getPromptText(el) {
  return el ? (el.value || el.innerText || el.textContent || "") : "";
}

function isPromptBox(el) {
  if (!el) return false;
  if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") return true;
  const ce = el.getAttribute("contenteditable");
  if (ce === "true" || ce === "plaintext-only" || ce === "") return true;
  if (el.getAttribute("role") === "textbox") return true;
  return false;
}

let lastActivePromptBox = null;

// Track the last element the user typed into
document.addEventListener("focus", (e) => {
  if (isPromptBox(e.target)) lastActivePromptBox = e.target;
}, true);
document.addEventListener("input", (e) => {
  if (isPromptBox(e.target)) lastActivePromptBox = e.target;
}, true);

// ── ENTER key intercept ──────────────────────────────────────
document.addEventListener("keydown", async (e) => {
  if (!interceptEnabled || e.key !== "Enter" || e.shiftKey || e.ctrlKey || e.isComposing) return;
  const active = document.activeElement;
  if (!isPromptBox(active)) return;
  
  const text = getPromptText(active).trim();
  if (text.length < 3) return;

  e.preventDefault();
  e.stopImmediatePropagation();
  interceptEnabled = false; // LOCK IMMEDIATELY

  await checkPrompt(text, (final) => {
    if (active.tagName === "TEXTAREA" || active.tagName === "INPUT") {
      active.value = final;
    } else {
      active.innerText = final;
      const r = document.createRange(), s = window.getSelection();
      r.selectNodeContents(active); r.collapse(false);
      s.removeAllRanges(); s.addRange(r);
    }

    active.dispatchEvent(new Event("input", { bubbles: true })); // alert React/Vue
    active.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, bubbles: true, cancelable: true }));
  }, () => { interceptEnabled = true; }); // ✅ onDone: always unlock, even after BLOCK
}, true);

// ── Send button intercept ─────────────────────────────────────
document.addEventListener("click", async (e) => {
  if (!interceptEnabled) return;
  
  // Broad selector for any "Send" or "Arrow" button in AI tools
  const btn = e.target.closest(
    "button[data-testid*='send' i]," +
    "button[aria-label*='send' i]," +
    "button[aria-label*='Submit' i]," +
    "button[aria-label*='Gemini' i]," +
    "button[class*='send' i]," +
    "button:has(svg)," +
    "button svg," +
    "div[role='button'][aria-label*='send' i]," +
    "div[role='button'][aria-label*='Grok' i]," +
    "mat-icon[aria-label*='send' i]," +
    ".send-button"
  );
  if (!btn) return;

  const actualBtn = (btn.tagName === 'SVG' || btn.tagName === 'PATH' || btn.tagName === 'MAT-ICON') ? 
                    (btn.closest('button') || btn.closest('div[role="button"]') || btn) : btn;
  if (!actualBtn) return;

  const area =
    lastActivePromptBox ||
    document.querySelector("textarea#prompt-textarea, textarea#chat-input, div#prompt-textarea, [contenteditable='true']") ||
    document.querySelector("textarea");

  if (!area || !isPromptBox(area)) return;

  const text = getPromptText(area).trim();
  if (text.length < 3) return;

  e.preventDefault();
  e.stopImmediatePropagation();

  await checkPrompt(text, (final) => {
    if (area.tagName === "TEXTAREA" || area.tagName === "INPUT") area.value = final;
    else area.innerText = final;

    area.dispatchEvent(new Event("input", { bubbles: true })); // alert React/Vue
    actualBtn.click();
  }, () => { interceptEnabled = true; }); // ✅ onDone: always unlock, even after BLOCK
}, true);

// ── Start notification ────────────────────────────────────────
const tool = detectTool();
if (tool !== "Unknown") {
  setTimeout(() => showToast(`🛡️ PromptGuard Active on ${tool}`, "allow"), 1500);
}
console.log("🛡️ PromptGuard active on", tool);
