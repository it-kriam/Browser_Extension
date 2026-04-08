# 🛡️ PromptGuard — Enterprise AI Firewall

> A Chrome/Edge/Brave/Firefox browser extension that intercepts every prompt sent
> to AI tools (ChatGPT, Gemini, Copilot, Claude), scans for sensitive data,
> and blocks, redacts, or alerts — all logged to a PostgreSQL database with
> a real-time Enterprise Security Dashboard.

---

## 🎯 What We Are Trying to Achieve

As organizations adopt Generative AI, they face a critical **Data Security Gap**. Sensitive information — ranging from PII and Health Data (PHI) to Internal Secrets and Source Code — is frequently leaked through LLM prompts.

**PromptGuard's Objective:**
1.  **Prevent Data Leakage:** Ensure no sensitive corporate or customer data leaves the perimeter.
2.  **Mitigate Jailbreaks:** Protect against prompt injections and adversarial attacks that try to bypass security constraints.
3.  **Enforce Corporate Policy:** Transition from "wild west" AI usage to governed, policy-backed interactions.
4.  **Full Auditability:** Provide security teams with a forensic trail of every prompt, its risk score, and the enforcement action taken.

---

## ⚙️ How It Works: The 3-Layer Defense

PromptGuard doesn't just look for keywords. It uses a **3-Layer Intelligent Funnel** to evaluate risks in real-time.

### 1. Interception Layer (The Extension)
A Manifest V3 browser extension sits in the user's browser. It intercepts every prompt sent to AI domains before it ever reaches the LLM server.

### 2. Multi-Layer Detection Funnel (The Backend)
Every prompt is sent to the Spring Boot security engine, which processes it through three distinct layers:
*   **Layer 1 (Pattern/Regex):** High-speed deterministic scanning for known formats (Credit Cards, SSNs, PHI, API Keys).
*   **Layer 2 (Semantic/NLP):** Intent-based analysis looking for "sharing" behavior or sensitive context that patterns miss.
*   **Layer 3 (Local LLM - Ollama):** Deep-reasoning layer using Llama3 to detect complex Jailbreak attempts, persona-playing, and sophisticated prompt injections.

### 3. Policy Enforcement Engine
Based on the risk score (0-100), the engine takes immediate action:
*   ✅ **ALLOW:** Safely passes the prompt through.
*   ⚠️ **ALERT:** Logs the event and shows a warning notification.
*   ✏️ **REDACT:** Strips sensitive data (e.g., `[REDACTED-PII]`) and sends only the safe text.
*   🚫 **BLOCK:** Completely stops the prompt and alerts the user.

---

## 📁 Project Structure

```
promptguard/
├── extension/                     ← Load this folder in Chrome/Edge/Brave
│   ├── manifest.json
│   ├── background.js              ← Service worker: heartbeat, role check, browser detect
│   ├── content.js                 ← Intercepts prompts on AI sites
│   ├── icons/
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   └── popup/
│       ├── popup.html             ← Extension popup UI
│       └── popup.js               ← Tabs: Test / Settings / Admin
│
├── frontend-dashboard/
│   └── index.html                 ← Open in any browser — no server needed
│
├── backend/
│   ├── pom.xml
│   └── src/main/
│       ├── resources/
│       │   ├── application.properties
│       │   └── schema.sql
│       └── java/com/promptguard/
│           ├── config/            ← DatabaseInitializer (migration + user seeding)
│           ├── controller/        ← REST API endpoints
│           ├── detector/          ← PII / PHI / Secret / Source Code / Keyword / Org-Keyword engines
│           ├── model/             ← PromptRequest, PromptResponse, RiskType, etc.
│           ├── repository/        ← SQL queries (JdbcTemplate)
│           └── service/           ← AuditService, PolicyEngine, PromptValidationService, etc.
│
└── README.md
```

---

## ✅ Prerequisites

| Tool | Minimum Version | Check Command |
|---|---|---|
| Java | 17 | `java -version` |
| Maven | 3.8 | `mvn -version` |
| PostgreSQL | 13 | `psql --version` |
| Ollama | Latest | `ollama --version` |
| Chrome/Edge/Brave | Any | — |

---

## 🚀 Step-by-Step Setup

### STEP 1 — Create PostgreSQL Database

Open **DBeaver** → right-click **Databases** → **Create New Database**

```
Database name:  browser_extension_final
```

---

### STEP 2 — Configure Database & Ollama

Open `backend/src/main/resources/application.properties`:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/browser_extension_final
spring.datasource.username=postgres
spring.datasource.password=YOUR_PASSWORD
```

---

### STEP 3 — Start the Backend

```powershell
cd backend
mvn clean spring-boot:run
```

**✅ Expected console output on first run:**
```
=== PromptGuard DB Init ===
✅ Seeded user: admin-user (ADMIN)
✅ Seeded user: rohan-user (USER)
✅ Seeded user: kushal-user (USER)
✅ Tables ready — users: 3
=== DB Init Complete ===
```

---

### STEP 4 — Load the Extension in Chrome/Edge/Brave

1. Open browser → address bar → `chrome://extensions` → Enter
2. Enable **Developer mode** toggle
3. Click **Load unpacked** and select the `extension/` folder
4. 🛡️ PromptGuard icon appears in your toolbar

---

### STEP 2.5 — Setup Ollama (For Layer 3 Security)

PromptGuard uses **Ollama** to run a local LLM (Llama3) for deep-reasoning security checks.

1.  **Download:** Install Ollama from [ollama.com](https://ollama.com).
2.  **Pull Model:** Run the following command in your terminal:
    ```bash
    ollama run llama3
    ```
3.  **Verify:** Ensure Ollama is running at `http://localhost:11434`.

---

## 🦙 Ollama Intelligence — Before vs. After

| Feature | Before Adding Ollama (L1 & L2 Only) | After Adding Ollama (L3 Active) |
| :--- | :--- | :--- |
| **Simple Leaks** | ✅ Detected (SSN, Email, CC) | ✅ Detected + Context Verified |
| **Jailbreak Detection** | ❌ Minimal coverage | ✅ **Full Protection** (Llama3 reasoning) |
| **Persona Attacks** | ❌ Bypassed (e.g. "Act as a dev") | ✅ **Blocked** (Intent identified) |
| **Data Privacy** | ✅ 100% Local | ✅ 100% Local (Data never leaves Org) |
| **Complexity** | Basic pattern matching | Deep semantic understanding |

**What we do before adding Ollama:**
The system runs in **Legacy Mode**. All Phase 0 checks default to `SAFE`, and security relies entirely on the static Regex and Semantic layers. This is useful for testing setup without LLM overhead.

**What we can do after adding Ollama:**
The **"Intelligence Layer"** wakes up. The firewall can now understand *why* a prompt might be risky, even if it doesn't contain a specific blocked keyword, providing a robust defense against evolving AI threats.

---

## 🔍 Detection Engines — Processing Order

Detectors run in **three phases** to ensure maximum security with minimal latency.

```
Phase 0 — Firewall Layer (Local LLM)
  ┌──────────────────────────────────────────────┐
  │  1. JailbreakDetector   Llama3 (Ollama)      │  ← High Priority
  └──────────────────────────────────────────────┘
          ↓ if no injection attempt found
Phase 1 — Global Detectors (Regex + Semantic)
  ┌──────────────────────────────────────────────┐
  │  2. SecretDetector      API keys, tokens     │
  │  3. PiiDetector         SSN, CC, Aadhaar     │  ← 3-Layer Funnel
  │  4. PhiDetector         HIPAA health data    │
  │  5. SourceCodeDetector  SQL / Java / Python  │
  │  6. KeywordDetector     Global block words   │
  └──────────────────────────────────────────────┘
          ↓ if Phase 1 finds nothing risky
Phase 2 — Org-specific (isolated per organisation)
  ┌──────────────────────────────────────────────┐
  │  7. UserKeywordDetector                      │
  │     WHERE user_id = ? AND sub_user = ?       │
  └──────────────────────────────────────────────┘
```

| Detector | What It Detects | Score | Action |
|---|---|---|---|
| `JailbreakDetector` | Prompt injections, persona playing | 85-100 | **BLOCK** |
| `SecretDetector` | API keys, AWS credentials, tokens | 100 | **BLOCK** |
| `PiiDetector` | SSN, credit card, Aadhaar, phone, email | 60–85 | REDACT |
| `PhiDetector` | MRN, ICD-10, NPI, medication, diagnosis | 65–80 | BLOCK / REDACT |
| `SourceCodeDetector` | SQL, Java, Python code | 50–70 | ALERT |
| `KeywordDetector` | Global block/alert keywords | 55–100 | BLOCK / ALERT |
| `UserKeywordDetector` | Org-specific keyword isolation | 75–100 | BLOCK / REDACT |

---

## 🏥 PHI Detector — HIPAA Safe Harbor

`PhiDetector` follows **HIPAA Safe Harbor** (45 CFR §164.514(b)).

| PHI Type | Example | Score | Action |
|---|---|---|---|
| MRN (Medical Record Number) | `MRN: 789456` | 80 | **BLOCK** |
| ICD-10 diagnosis code | `E11.9`, `J18.9` | 80 | **BLOCK** |
| NPI (Provider Identifier) | `NPI: 1234567890` | 80 | **BLOCK** |
| Date of birth | `DOB: 15/03/1990` | 75 | REDACT |
| Healthcare IDs | `member id: ABC123` | 65 | REDACT |

---

## ⚙️ Policy Actions

| Action | Risk Level | What Happens | User Sees |
|---|---|---|---|
| `ALLOW` | NONE / LOW | Prompt sent through silently | Nothing |
| `ALERT` | MEDIUM | Prompt sent + warning shown | ⚠️ Orange toast |
| `REDACT` | HIGH | Sensitive text removed, rest sent | ✏️ Purple toast |
| `BLOCK` | CRITICAL | Prompt completely stopped | 🚫 Red toast |

---

## 📝 Changelog

### pg_v14 (current)
- **NEW** `JailbreakDetector` — Integrated Local LLM (Ollama/Llama3) for advanced prompt injection detection.
- **NEW** 3-Layer Funnel architecture (Regex, Semantic, LLM) for intelligent scoring.
- **NEW** Expanded detectors: Cryptocurrency, IP Addresses, JWT, and Cloud Provider configs.
- **IMPROVED** Dashboard analytics for token usage and organizational risk profiling.

### pg_v11
- Initial release with HIPAA PHI detection and Org-based keyword isolation.

---

*PromptGuard v14 — Enterprise AI Security with Local LLM & Multi-Layer Detection*

