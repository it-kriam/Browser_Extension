package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * JailbreakDetector — High-Performance Prompt Injection Shield.
 * L1: Fast matching for known jailbreak strings (100% confidence).
 * L2: Semantic persona + instruction override + bypass intent detection.
 * Short-circuit: L1 score=100 → L2 skipped (BLOCK already decided).
 */
@Component
public class JailbreakDetector implements Detector {

    // ── L1: Structural Regex Patterns ─────────────────────────────────────
    private static final List<Pattern> JAILBREAK_PATTERNS = List.of(
        Pattern.compile("\\b(DAN|STAN|DUDE|JAILBREAK)\\s+mode\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ignore (previous|all|your|the) instructions", Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "(disregard|forgot|forget|override) (all|previous|the|your) " +
            "(rules|history|instructions|guidelines|constraints)",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "you are now a (hacker|criminal|unrestricted AI|evil AI|bad actor)",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile("system (override|prompt injection|instruction override)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("developer mode (enabled|on|activated)", Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "(act|behave) (as if you have no|without any) (restrictions|filters|rules|guidelines)",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "(do not|don't) (follow|apply|adhere to) (your|any|the) (guidelines|rules|filters|safety)",
            Pattern.CASE_INSENSITIVE)
    );

    // ── L2: Semantic Keywords ─────────────────────────────────────────────
    private static final List<String> PERSONA_WORDS = List.of(
        "act as", "pretend to be", "imagine you are", "stay in character",
        "roleplay as", "you are now", "simulate being", "act like you are",
        "behave as", "from now on you are", "your new persona", "embody",
        "take on the role of", "respond as if you were"
    );

    private static final List<String> BYPASS_WORDS = List.of(
        "no rules", "unrestricted", "no restrictions", "no limits",
        "without filters", "no guidelines", "do anything", "no ethics",
        "bypass", "override", "uncensored", "no safety", "forget your training",
        "ignore safety", "skip guardrails", "remove all restrictions",
        "pretend you have no limits", "unfiltered"
    );

    private static final List<String> INSTRUCTION_OVERRIDE = List.of(
        "new instructions", "updated instructions", "your real instructions",
        "disregard everything", "ignore everything above", "new task:",
        "your actual goal", "your hidden goal", "forget previous context",
        "start fresh with", "override system prompt", "system: you are"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "JailbreakDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX (Original Text — Short-circuits) ────────────────
        if (runRegexLayer(prompt, results)) return results;

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        for (Pattern p : JAILBREAK_PATTERNS) {
            if (p.matcher(prompt).find()) {
                results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 100,
                    "L1_JAILBREAK: Malicious injection pattern", prompt));
                return true;
            }
        }
        return false;
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexLayer(original, new ArrayList<>())) {
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 20, "L2_JAILBREAK_INQUIRY",
                "INFO: User is inquiring about jailbreak safety, not attempting one."));
            return;
        }

        boolean hasPersona             = PERSONA_WORDS.stream().anyMatch(normalized::contains);
        boolean hasBypass              = BYPASS_WORDS.stream().anyMatch(normalized::contains);
        boolean hasInstructionOverride = INSTRUCTION_OVERRIDE.stream().anyMatch(normalized::contains);

        if (hasPersona && hasBypass) {
            // Both persona + bypass → BLOCK (≥80)
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 95,
                "L2_JAILBREAK_PERSONA_BYPASS: Roleplay + bypass intent combo detected", original));
        } else if (hasInstructionOverride) {
            // Instruction override alone → BLOCK (≥80)
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 90,
                "L2_JAILBREAK_INSTRUCTION_OVERRIDE: Prompt injection via instruction override", original));
        } else if (hasBypass) {
            // Bypass/restriction removal alone → REDACT (60-79)
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 70,
                "L2_JAILBREAK_BYPASS: Suspicious restriction bypass attempt detected", original));
        } else if (hasPersona) {
            // Persona shaping alone (e.g. "act as a chef") → ALERT (40-59)
            results.add(new DetectionResult(RiskType.PROMPT_INJECTION, 50,
                "L2_JAILBREAK_PERSONA: Suspicious behavior-shaping attempt detected", original));
        }
    }
}
