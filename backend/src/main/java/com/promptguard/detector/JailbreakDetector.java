package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * JailbreakDetector — 3-Layer Intelligent Injection Shield.
 * L1: Exact matching for known jailbreak strings (DAN, STAN, etc).
 * L2: Semantic persona and instruction override detection.
 * L3: LLM reasoning for subtle behavioral manipulations.
 */
@Component
public class JailbreakDetector implements Detector {

    private static final List<Pattern> JAILBREAK_PATTERNS = List.of(
        Pattern.compile("\\b(DAN|STAN|DUDE)\\s+mode\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ignore previous instructions", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard all rules", Pattern.CASE_INSENSITIVE),
        Pattern.compile("you are now a hacker", Pattern.CASE_INSENSITIVE)
    );

    private static final List<String> PERSONA_WORDS = Arrays.asList("act as", "pretend to be", "imagine you are", "stay in character");

    public JailbreakDetector() {
    }

    @Override
    public String getName() {
        return "JailbreakDetector";
    }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        return detect(context.getPrompt(), context.getDecision());
    }

    public List<DetectionResult> detect(String prompt, OllamaService.LlmDecision decision) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX ───────────────────────────────────────────
        if (runRegexLayer(prompt, results)) return results;

        // ── LAYER 2: SEMANTIC ────────────────────────────────────────
        runSemanticLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 3: LLM (Reusing shared decision) ───────────────────
        runLlamaLayer(prompt, results, decision);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        for (Pattern p : JAILBREAK_PATTERNS) {
            if (p.matcher(prompt).find()) {
                results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 100, "L1_JAILBREAK: Known malicious pattern", prompt));
                return true;
            }
        }
        return false;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        boolean hasPersona = PERSONA_WORDS.stream().anyMatch(w -> lower.contains(w));
        if (hasPersona && (lower.contains("no rules") || lower.contains("unrestricted"))) {
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 90, "L2_PERSONA_OVERRIDE: Suspicious roleplay detected", prompt));
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 85 && ("BLOCK".equals(decision.action) || decision.reason.toUpperCase().contains("JAILBREAK") || decision.reason.toUpperCase().contains("INJECTION"))) {
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, decision.score, "L3_JAILBREAK_LLM: " + decision.reason, prompt));
        }
    }
}
