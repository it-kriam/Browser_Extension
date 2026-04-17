package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JwtDetector — High-Performance JWT Shield.
 * L1: Regex detection for Header.Payload.Signature format + Base64 payload decode.
 * L2: Semantic intent for authentication token sharing.
 * Short-circuit: L1 hit (score=90) → L2 skipped.
 */
@Component
public class JwtDetector implements Detector {

    // ── L1: JWT Structure Pattern ─────────────────────────────────────────
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "\\b(eyJ[A-Za-z0-9_-]{10,})\\.([A-Za-z0-9_-]{10,})\\.([A-Za-z0-9_-]{20,})\\b");

    // ── L2: High-Risk Auth Token Keywords (score=80) ──────────────────────
    private static final List<String> AUTH_TOKEN_KEYWORDS = List.of(
        "jwt", "json web token", "bearer token", "access token",
        "refresh token", "id token", "auth token", "authorization bearer",
        "x-auth-token", "authorization header", "token authentication",
        "oauth token", "oidc token", "saml token", "session token",
        "api token", "service token", "machine token"
    );

    // ── L2: Medium-Risk Auth Context Keywords (score=65) ──────────────────
    private static final List<String> AUTH_CONTEXT_KEYWORDS = List.of(
        "token expiry", "token refresh", "token validation", "token decode",
        "jwt payload", "jwt claims", "jwt secret", "signing key",
        "token scope", "token audience", "token issuer", "token subject",
        "cookie session", "session id", "csrf token", "xsrf token",
        "api key header", "authorization flow", "sso token"
    );

    // ── L2: Low-Risk Auth Discussion Keywords (score=50) ──────────────────
    private static final List<String> AUTH_DISCUSSION_KEYWORDS = List.of(
        "authentication", "login token", "logout token", "token rotation",
        "token blacklist", "token revocation", "token store",
        "token middleware", "auth middleware", "auth interceptor",
        "jwt library", "jsonwebtoken", "nimbus jwt"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "JwtDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX + Base64 Decode (Original Text — Short-circuits) ──
        if (runRegexLayer(prompt, results)) return results;

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        Matcher m = JWT_PATTERN.matcher(prompt);
        if (m.find()) {
            String fullToken = m.group();
            String description = buildDescription(m.group(2)); // group(2) = payload
            results.add(new DetectionResult(RiskType.SECRET, 90,
                "L1_JWT_REGEX: " + description, fullToken));
            return true;
        }
        return false;
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexLayer(original, new ArrayList<>())) {
            results.add(new DetectionResult(RiskType.SECRET, 20, "L2_JWT_INQUIRY",
                "INFO: User is inquiring about JWT safety, not disclosing tokens."));
            return;
        }

        // Tier 1: Named token mention (jwt, bearer, access token) → REDACT (60-79)
        for (String kw : AUTH_TOKEN_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").replace("-", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.SECRET, 65,
                    "L2_JWT_TOKEN: " + kw, kw));
                return;
            }
        }
        // Tier 2: Auth implementation context → ALERT (40-59)
        for (String kw : AUTH_CONTEXT_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").replace("-", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.SECRET, 50,
                    "L2_JWT_CONTEXT: " + kw, kw));
                return;
            }
        }
        // Tier 3: General auth discussion → ALLOW (safe educational)
        for (String kw : AUTH_DISCUSSION_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").replace("-", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.SECRET, 35,
                    "L2_JWT_DISCUSSION: " + kw, kw));
                return;
            }
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
