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
 * SecretDetector — 3-Layer Intelligent Shield.
 * L1: Fast Regex Matching
 * L2: Semantic Intent Analysis
 * L3: Local LLM (Llama3) Reasoning
 */
@Component
public class SecretDetector implements Detector {

    private static final List<Pattern> SECRET_PATTERNS = List.of(
            Pattern.compile("(?:password|passwd|pwd|api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)(?:\\s+is\\s+|\\s*[=:]\\s*)[\\w!@#$%^&*]+", Pattern.CASE_INSENSITIVE|Pattern.MULTILINE),
            Pattern.compile("(?i)bearer\\s+[A-Za-z0-9\\-._~+/]+=*", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)jdbc:[a-z]+://[^\\s]*password=[^\\s&]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
            Pattern.compile("ghp_[A-Za-z0-9]{30,60}"),
            Pattern.compile("sk-[A-Za-z0-9]{20,80}"),
            Pattern.compile("AKIA[0-9A-Z]{12,25}")
    );

    private static final List<String> OWNERSHIP_WORDS = Arrays.asList("my", "i", "me", "our");
    private static final List<String> SENSITIVE_WORDS = Arrays.asList("password", "login", "api key", "auth", "credential", "secret", "token", "pk", "passcode");
    private static final List<String> SHARING_WORDS = Arrays.asList("is", "are", "here is", "giving", "sharing", "save", "store");

    public SecretDetector() {
    }

    @Override
    public String getName() {
        return "SecretDetector";
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
        for (Pattern pattern : SECRET_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 100, "L1_EXACT_SECRET", m.group()));
                return true; 
            }
        }
        return false;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lowerPrompt = prompt.toLowerCase();
        boolean hasOwnership = OWNERSHIP_WORDS.stream().anyMatch(w -> lowerPrompt.matches(".*\\b" + w + "\\b.*"));
        boolean hasSensitive = SENSITIVE_WORDS.stream().anyMatch(w -> lowerPrompt.matches(".*\\b" + w + "\\b.*"));
        boolean hasSharing = SHARING_WORDS.stream().anyMatch(w -> lowerPrompt.matches(".*\\b" + w + "\\b.*"));

        if (hasOwnership && hasSensitive && hasSharing) {
            results.add(new DetectionResult(RiskType.SECRET, 95, "L2_SECRET_INTENT", "Potential secret sharing intent detected."));
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 85 && (decision.reason.toUpperCase().contains("SECRET") || "BLOCK".equals(decision.action))) {
            results.add(new DetectionResult(RiskType.SECRET, decision.score, "L3_SECRET_LLM: " + decision.reason, prompt));
        }
    }
}
