package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PiiDetector — 3-Layer Intelligent PII Shield.
 * L1: Fast Regex Matching
 * L2: Semantic Intent Analysis
 * L3: Local LLM (Llama3) Reasoning
 */
@Component
public class PiiDetector implements Detector {

    private static final Pattern EMAIL = Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");
    private static final Pattern PHONE = Pattern.compile("(\\+91[\\-\\s]?)?[6-9]\\d{9}");
    private static final Pattern AADHAAR = Pattern.compile("\\b[2-9]\\d{3}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}\\b");
    private static final Pattern PAN = Pattern.compile("\\b[A-Z]{5}[0-9]{4}[A-Z]\\b");
    private static final Pattern SSN = Pattern.compile("\\b\\d{3}[\\s\\-]?\\d{2}[\\s\\-]?\\d{4}\\b");
    private static final Pattern CREDIT = Pattern.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:\\d[ -]?){13,19})\\b");

    private static final List<String> OWNERSHIP_WORDS = Arrays.asList("my", "i", "me", "our");
    private static final List<String> SENSITIVE_WORDS = Arrays.asList("password", "login", "api key", "card", "bank", "account details", "otp", "aadhaar", "pan");
    private static final List<String> SHARING_WORDS = Arrays.asList("is", "are", "here is", "giving", "sharing");

    public PiiDetector() {
    }

    @Override
    public String getName() {
        return "PiiDetector";
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
        boolean match = false;
        match |= checkAndAdd(prompt, EMAIL, "EMAIL", 60, results);
        match |= checkAndAdd(prompt, PHONE, "PHONE", 65, results);
        match |= checkAndAdd(prompt, AADHAAR, "AADHAAR", 70, results);
        match |= checkAndAdd(prompt, PAN, "PAN", 70, results);
        match |= checkAndAdd(prompt, SSN, "SSN", 75, results);
        match |= checkAndAdd(prompt, CREDIT, "CREDIT_CARD", 75, results);
        return match;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        boolean hasOwnership = OWNERSHIP_WORDS.stream().anyMatch(w -> lower.matches(".*\\b" + w + "\\b.*"));
        boolean hasSensitive = SENSITIVE_WORDS.stream().anyMatch(w -> lower.matches(".*\\b" + w + "\\b.*"));
        boolean hasSharing = SHARING_WORDS.stream().anyMatch(w -> lower.matches(".*\\b" + w + "\\b.*"));
        if ((hasOwnership ? 1 : 0) + (hasSensitive ? 1 : 0) + (hasSharing ? 1 : 0) >= 2) {
            results.add(new DetectionResult(RiskType.PII, 85, "L2_PII_INTENT", "Potential PII sharing intent detected."));
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 80 && (decision.reason.toUpperCase().contains("PII") || "BLOCK".equals(decision.action))) {
            results.add(new DetectionResult(RiskType.PII, decision.score, "L3_PII_LLM: " + decision.reason, prompt));
        }
    }

    private boolean checkAndAdd(String prompt, Pattern p, String label, int score, List<DetectionResult> results) {
        Matcher m = p.matcher(prompt);
        if (m.find()) {
            results.add(new DetectionResult(RiskType.PII, score, "L1_PII_REGEX: " + label, m.group()));
            return true;
        }
        return false;
    }
}
