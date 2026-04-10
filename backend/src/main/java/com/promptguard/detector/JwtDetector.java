package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JwtDetector — 3-Layer Intelligent JWT Shield.
 * L1: Regex detection for Header.Payload.Signature format.
 * L2: Semantic intent for authentication token sharing.
 * L3: LLM reasoning for obfuscated tokens or login flows.
 */
@Component
public class JwtDetector implements Detector {

    // JWT structure: 3 Base64URL segments separated by dots.
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "\\b(eyJ[A-Za-z0-9_-]{10,})\\.([A-Za-z0-9_-]{10,})\\.([A-Za-z0-9_-]{20,})\\b"
    );

    // Common JWT and authentication token keywords
    private static final Set<String> JWT_KEYWORDS = Set.of(
        "jwt", "json web token", "bearer token", "access token", 
        "refresh token", "id token", "auth token", "authorization bearer",
        "x-auth-token"
    );

    public JwtDetector() {
    }

    @Override
    public String getName() {
        return "JwtDetector";
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
        Matcher m = JWT_PATTERN.matcher(prompt);
        if (m.find()) {
            String fullToken = m.group();
            String description = buildDescription(m.group(2)); // group(2) = payload
            results.add(new DetectionResult(RiskType.SECRET, 90, "L1_JWT: " + description, fullToken));
            return true;
        }
        return false;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : JWT_KEYWORDS) {
            if (lower.contains(kw)) {
                results.add(new DetectionResult(RiskType.SECRET, 80, "L2_JWT_KEYWORD: " + kw, kw));
                return;
            }
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 80 && (decision.reason.toUpperCase().contains("JWT") || decision.reason.toUpperCase().contains("AUTH TOKEN") || decision.reason.toUpperCase().contains("SESSION"))) {
            results.add(new DetectionResult(RiskType.SECRET, decision.score, "L3_JWT_LLM: " + decision.reason, prompt));
        }
    }

    private String buildDescription(String payloadB64) {
        try {
            int pad = (4 - payloadB64.length() % 4) % 4;
            String padded = payloadB64 + "=".repeat(pad);
            String payloadJson = new String(Base64.getUrlDecoder().decode(padded));

            String subject = extractClaim(payloadJson, "sub");
            String email   = extractClaim(payloadJson, "email");
            String issuer  = extractClaim(payloadJson, "iss");

            StringBuilder sb = new StringBuilder("JWT detected");
            if (!issuer.isEmpty())  sb.append(" Issuer: ").append(issuer);
            if (!subject.isEmpty()) sb.append(" Subject: ").append(subject);
            if (!email.isEmpty())   sb.append(" Email: ").append(email);
            return sb.toString();

        } catch (Exception e) {
            return "JWT detected — live auth token.";
        }
    }

    private String extractClaim(String json, String key) {
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"?([^\",}]+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1).trim() : "";
    }
}
