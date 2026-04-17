package com.promptguard.service;

import com.promptguard.model.*;
import org.springframework.stereotype.Service;

@Service
public class PolicyEngine {

    /**
     * Decision priority (ORDER MATTERS):
     *
     * 1. SECRET      → BLOCK  (credentials must never reach AI)
     * 2. KEYWORD     → BLOCK  (global admin-defined forbidden words)
     * 3. ORG_KEYWORD → 4 possible outcomes based on score:
     *                    score=100 → BLOCK    (block_col)    absolute block
     *                    score=85  → ALERT    (critial_col)  critical severity alert ← FIXED
     *                    score=75  → REDACT   (redacted_col) remove keyword, send rest
     *                    score=0   → ALLOW    (allow_col)    never reaches here (skipped in detector)
     * 4. PHI         → BLOCK if score≥80 (MRN/ICD/NPI), else REDACT
     * 5. PII         → REDACT (SSN, CC, Aadhaar, PAN, phone, email)
     * 6. SOURCE_CODE → ALERT
     * 7. 80-100      → BLOCK
     * 8. 60-79       → REDACT
     * 9. 40-59       → ALERT (Critical)
     * 10. 0-39       → ALLOW (Safe)
     */
    public PolicyDecision decide(RiskScore riskScore) {
        int      score = riskScore.getTotalScore();
        RiskType type  = riskScore.getRiskType();

        // ── PRIORITY 1: GLOBAL BLOCK (Standard 80+ Threshold) ────────────────
        if (score >= 80) {
            String reason = "Severe security risk automatically blocked. ";
            if (type == RiskType.SECRET) reason = "Credential/Secret detected. ";
            if (type == RiskType.KEYWORD) reason = "Strictly blocked keyword detected. ";
            if (type == RiskType.PHI) reason = "Sensitive Medical Conditions or identifiers detected. ";
            if (type == RiskType.PII) reason = "High-confidence PII disclosure intent detected. ";
            if (type == RiskType.ORG_KEYWORD) reason = "Organisation policy: keyword is on the BLOCK list. ";
            if (type == RiskType.PROMPT_INJECTION) reason = "Malicious prompt injection or jailbreak attempt detected. ";
            
            return new PolicyDecision(Action.BLOCK, reason + "Content cannot be sent to AI tools (Score: " + score + ").");
        } 
        
        // ── PRIORITY 2: REDACT (Standard 60-79 Threshold) ─────────────────────
        if (score >= 60) {
            String reason = "High-risk content detected. ";
            if (type == RiskType.PII) reason = "Personally Identifiable Information (PII) detected. ";
            if (type == RiskType.PHI) reason = "Protected Health Information (PHI) identifiers detected. ";
            if (type == RiskType.ORG_KEYWORD) reason = "Organisation policy: sensitive keyword redacted. ";
            
            return new PolicyDecision(Action.REDACT, reason + "Content was safe-guarded before sending (Score: " + score + ").");
        }

        // ── PRIORITY 3: ALERT (Standard 40-59 Threshold) ──────────────────────
        if (score >= 40) {
            String reason = "Medium/Critical risk alert. ";
            if (type == RiskType.PII) reason = "Potential PII context detected. ";
            if (type == RiskType.SOURCE_CODE) reason = "Source code or SQL query detected. ";
            if (type == RiskType.ORG_KEYWORD) reason = "Organisation policy: CRITICAL keyword alert. ";
            
            return new PolicyDecision(Action.ALERT, reason + "Review recommended before submission (Score: " + score + ").");
        }

        // ── PRIORITY 4: ALLOW (Safe) ──────────────────────────────────────────
        return new PolicyDecision(Action.ALLOW, "No significant risk detected.");
    }
}
