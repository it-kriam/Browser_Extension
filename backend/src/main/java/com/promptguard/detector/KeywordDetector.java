package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * KeywordDetector — 3-Layer Intelligent Policy Shield.
 * L1: Exact matching for Blocked and Sensitive keywords.
 * L2: Semantic intent for policy circumvention.
 * L3: LLM reasoning for subtle policy violations.
 */
@Component
public class KeywordDetector implements Detector {

    // ── BLOCK tier: score=100 ──
    private static final Set<String> BLOCK_KEYWORDS = Set.of(
        "bypass security", "ignore safety", "ignore previous instructions",
        "jailbreak", "disregard your instructions", "root password",
        "sudo password", "production credentials", "layoff plan"
    );

    // ── ALERT tier: score=55 ──
    private static final Set<String> ALERT_KEYWORDS = Set.of(
        "confidential", "top secret", "internal use only",
        "proprietary", "acquisition target", "merger talks"
    );

    public KeywordDetector() {
    }

    @Override
    public String getName() {
        return "KeywordDetector";
    }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        return detect(context.getPrompt(), context.getDecision());
    }

    public List<DetectionResult> detect(String prompt, OllamaService.LlmDecision decision) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX / EXACT ───────────────────────────────────
        if (runRegexLayer(prompt, results)) return results;

        // ── LAYER 2: SEMANTIC ────────────────────────────────────────
        runSemanticLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 3: LLM (Reusing shared decision) ───────────────────
        runLlamaLayer(prompt, results, decision);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : BLOCK_KEYWORDS) {
            if (lower.contains(kw)) {
                results.add(new DetectionResult(RiskType.KEYWORD, 100, "Blocked keyword: " + kw, kw));
                return true;
            }
        }
        for (String kw : ALERT_KEYWORDS) {
            if (lower.contains(kw)) {
                results.add(new DetectionResult(RiskType.SOURCE_CODE, 55, "Sensitive keyword: " + kw, kw));
                return true;
            }
        }
        return false;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        // Look for combinations like "how to" + "bypass" or "tell me" + "secret"
        if (lower.contains("how to") && (lower.contains("bypass") || lower.contains("crack"))) {
            results.add(new DetectionResult(RiskType.KEYWORD, 80, "L2_POLICY_INTENT: Security bypass instructions", prompt));
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 75 && (decision.reason.toUpperCase().contains("BYPASS") || decision.reason.toUpperCase().contains("POLICY") || decision.reason.toUpperCase().contains("RESTRICTION"))) {
            results.add(new DetectionResult(RiskType.KEYWORD, decision.score, "L3_KEYWORD_LLM: " + decision.reason, prompt));
        }
    }
}
