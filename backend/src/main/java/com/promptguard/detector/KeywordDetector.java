package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * KeywordDetector — High-Performance Policy Shield.
 * L1: Exact matching for Blocked (score=100) and Sensitive (score=55) keywords.
 * L2: Semantic intent for security bypass and circumvention attempts.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class KeywordDetector implements Detector {

    // ── L1: BLOCK tier — score=100 (instant BLOCK) ────────────────────────
    private static final Set<String> BLOCK_KEYWORDS = Set.of(
        "bypass security", "ignore safety", "ignore previous instructions",
        "jailbreak", "disregard your instructions", "root password",
        "sudo password", "production credentials", "layoff plan",
        "admin credentials", "master password", "escalate privileges",
        "drop table", "delete database", "format disk", "rm -rf",
        "shutdown server", "disable firewall", "disable antivirus"
    );

    // ── L1: ALERT tier — score=55 (audit flagged) ─────────────────────────
    private static final Set<String> ALERT_KEYWORDS = Set.of(
        "confidential", "top secret", "internal use only",
        "proprietary", "acquisition target", "merger talks",
        "trade secret", "board meeting", "executive compensation",
        "unreleased product", "pre-announcement", "embargoed",
        "nda", "non-disclosure", "restricted distribution"
    );

    // ── L2: Security Bypass Intent ────────────────────────────────────────
    private static final List<String> BYPASS_INTENT_PREFIXES = List.of(
        "how to", "tell me how", "show me how", "teach me",
        "explain how to", "steps to", "guide to", "tutorial for",
        "ways to", "methods to", "instructions for"
    );

    private static final List<String> BYPASS_ACTIONS = List.of(
        "bypass", "crack", "hack", "exploit", "break into",
        "circumvent", "evade", "get around", "defeat", "override",
        "disable", "remove restrictions", "escalate privileges",
        "brute force", "sql injection", "xss attack", "reverse engineer"
    );

    // ── L2: Data Exfiltration Intent ──────────────────────────────────────
    private static final List<String> EXFILTRATION_KEYWORDS = List.of(
        "extract data", "dump database", "export all records",
        "scrape user data", "copy customer list", "download all files",
        "bulk export", "mass download", "steal data", "data exfiltration"
    );

    private static final java.util.regex.Pattern INQUIRY_PATTERN = java.util.regex.Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        java.util.regex.Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "KeywordDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: EXACT MATCH (Original + Normalized) ──────────────────
        if (runRegexLayer(prompt, normalized, results)) return results;

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private boolean runRegexLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        
        // Check original first for precision
        for (String kw : BLOCK_KEYWORDS) {
            if (lowerOrig.contains(kw) || normalized.contains(kw.replace(" ", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.KEYWORD, 100,
                    "L1_KEYWORD_BLOCK: " + kw, kw));
                return true;
            }
        }
        for (String kw : ALERT_KEYWORDS) {
            if (lowerOrig.contains(kw) || normalized.contains(kw.replace(" ", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.SOURCE_CODE, 55,
                    "L1_KEYWORD_ALERT: " + kw, kw));
                return true;
            }
        }
        return false;
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexCheckOnly(original)) {
            results.add(new DetectionResult(RiskType.KEYWORD, 20, "L2_POLICY_INQUIRY",
                "INFO: User is inquiring about security policy, not attempting a bypass."));
            return;
        }

        // Check for bypass intent: prefix + action combo (against normalized)
        boolean hasPrefix = BYPASS_INTENT_PREFIXES.stream().anyMatch(pre -> normalized.contains(pre.replace(" ", "")));
        boolean hasAction = BYPASS_ACTIONS.stream().anyMatch(act -> normalized.contains(act.replace(" ", "")));

        if (hasPrefix && hasAction) {
            results.add(new DetectionResult(RiskType.KEYWORD, 85,
                "L2_KEYWORD_BYPASS_INTENT: Security bypass how-to attempt", original));
            return;
        }

        // Check for data exfiltration intent
        for (String kw : EXFILTRATION_KEYWORDS) {
            if (lowerOrig.contains(kw)) {
                results.add(new DetectionResult(RiskType.KEYWORD, 80,
                    "L2_KEYWORD_EXFILTRATION: " + kw, kw));
                return;
            }
        }

        // Check standalone bypass action (lower confidence)
        if (hasAction) {
            results.add(new DetectionResult(RiskType.KEYWORD, 60,
                "L2_KEYWORD_SUSPICIOUS: Suspicious security action keyword detected", original));
        }
    }

    private boolean runRegexCheckOnly(String prompt) {
        String lower = prompt.toLowerCase();
        for (String kw : BLOCK_KEYWORDS) if (lower.contains(kw)) return true;
        for (String kw : ALERT_KEYWORDS) if (lower.contains(kw)) return true;
        return false;
    }
}
