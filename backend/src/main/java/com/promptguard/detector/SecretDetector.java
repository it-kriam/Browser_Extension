package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SecretDetector — High-Performance Credentials Shield.
 * L1: Fast Regex Matching (API keys, Bearer tokens, RSA keys, platform tokens).
 * L2: Semantic Intent Analysis — detects credential sharing intent without raw secret.
 * Short-circuit: L1 hits score=100 → L2 skipped (BLOCK already decided).
 */
@Component
public class SecretDetector implements Detector {

    // ── L1: Structural Regex Patterns ─────────────────────────────────────
    private static final List<Pattern> SECRET_PATTERNS = List.of(
        Pattern.compile(
            "(?:password|passwd|pwd|api[_-]?key|secret[_-]?key|access[_-]?token" +
            "|auth[_-]?token|private[_-]?key)(?:\\s+is\\s+|\\s*[=:]\\s*)[\\w!@#$%^&*]+",
            Pattern.CASE_INSENSITIVE | Pattern.MULTILINE),
        Pattern.compile("(?i)bearer\\s+[A-Za-z0-9\\-._~+/]+=*"),
        Pattern.compile("(?i)jdbc:[a-z]+://[^\\s]*password=[^\\s&]+"),
        Pattern.compile("-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
        Pattern.compile("ghp_[A-Za-z0-9]{10,60}"),
        Pattern.compile("sk-[A-Za-z0-9]{20,80}"),
        Pattern.compile("AKIA[0-9A-Z]{12,25}")
    );

    // ── L2: Semantic Keywords (plain contains — fast and safe) ────────────
    private static final List<String> OWNERSHIP_WORDS = List.of(
        "my", "i", "me", "our", "we", "his", "her", "their", "your"
    );

    private static final List<String> SENSITIVE_WORDS = List.of(
        "password", "login", "api key", "auth", "credential", "secret",
        "token", "passphrase", "passcode", "private key", "access key",
        "encryption key", "signing key", "ssh key", "pgp key", "client secret",
        "client id", "service account", "bearer", "refresh token", "pat token",
        "personal access token", "secret key", "hash key", "hmac key"
    );

    private static final List<String> SHARING_WORDS = List.of(
        "is", "are", "here is", "giving", "sharing", "save", "store",
        "use this", "take this", "here are", "sending", "submitting",
        "paste", "pasting", "copy", "check this", "use these credentials"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "SecretDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX (Original Text) ────────────────────────────────
        if (runRegexCheckOnly(prompt)) {
            runRegexLayer(prompt, results);
            return results;
        }

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private boolean runRegexCheckOnly(String prompt) {
        for (Pattern p : SECRET_PATTERNS) if (p.matcher(prompt).find()) return true;
        return false;
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

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");
        
        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexCheckOnly(original)) {
            results.add(new DetectionResult(RiskType.SECRET, 20, "L2_SECRET_INQUIRY",
                "INFO: User is inquiring about credential safety, not disclosing them."));
            return;
        }

        boolean hasOwnership = OWNERSHIP_WORDS.stream().anyMatch(normalized::contains);
        boolean hasSensitive = SENSITIVE_WORDS.stream().anyMatch(normalized::contains);
        boolean hasSharing   = SHARING_WORDS.stream().anyMatch(normalized::contains);

        if (hasOwnership && hasSensitive && hasSharing) {
            // All 3: ownership + sensitive + active sharing → BLOCK (≥80)
            results.add(new DetectionResult(RiskType.SECRET, 95, "L2_SECRET_FULL_INTENT",
                "CRITICAL: High-confidence credential sharing intent detected."));
        } else if (hasSensitive && hasSharing) {
            // Sensitive + sharing action, no ownership → REDACT (60-79)
            results.add(new DetectionResult(RiskType.SECRET, 65, "L2_SECRET_PARTIAL_INTENT",
                "WARNING: Potential credential disclosure pattern detected."));
        } else if (hasSensitive) {
            // Credential topic mentioned without sharing context → ALERT (40-59)
            results.add(new DetectionResult(RiskType.SECRET, 45, "L2_SECRET_MENTION",
                "INFO: Credential-related topic mentioned in prompt."));
        }
    }
}
