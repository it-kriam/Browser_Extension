package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JwtDetector — detects JSON Web Tokens (JWTs) embedded in prompts.
 *
 * Use-cases caught:
 *  - Access tokens / ID tokens pasted from app configs or curl commands
 *  - Authorization Bearer tokens in log snippets
 *  - Refresh tokens accidentally included in support tickets
 *  - JWTs from Postman/Insomnia environment dumps
 *
 * Format: header.payload.signature  (Base64URL-encoded, each part separated by '.')
 *
 * Risk model:
 *  - Score 90 → the token itself is a live credential  → PolicyEngine → BLOCK
 *  - We also attempt to decode the payload and surface the 'sub'/'email'/'iss'
 *    claims so the audit log is enriched without storing the raw token.
 */
@Component
public class JwtDetector {

    // JWT structure: 3 Base64URL segments separated by dots.
    // Header and payload must be at least 10 chars; signature at least 20.
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "\\b(eyJ[A-Za-z0-9_-]{10,})\\.([A-Za-z0-9_-]{10,})\\.([A-Za-z0-9_-]{20,})\\b"
    );

    // Common JWT and authentication token keywords
    private static final Set<String> JWT_KEYWORDS = Set.of(
        "jwt", "json web token", "bearer token", "access token", 
        "refresh token", "id token", "auth token", "authorization: bearer",
        "x-auth-token"
    );

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        Matcher m = JWT_PATTERN.matcher(prompt);
        while (m.find()) {
            String fullToken = m.group();
            String description = buildDescription(m.group(2)); // group(2) = payload part
            results.add(new DetectionResult(
                    RiskType.SECRET,
                    90,   // 85-90 range — use 90 so PolicyEngine always routes to BLOCK
                    description,
                    fullToken
            ));
        }

        // Keyword checks
        checkKeywords(prompt, JWT_KEYWORDS, "JWT Keyword", 80, results);

        return results;
    }

    private void checkKeywords(String prompt, Set<String> keywords, String label,
                                int score, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : keywords) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(
                    RiskType.SECRET,
                    score,
                    "Secret detected: " + label + " — \"" + kw + "\"",
                    kw
                ));
                return; // one hit per category is enough
            }
        }
    }

    /**
     * Attempts a best-effort decode of the JWT payload to enrich the audit
     * description. Does NOT throw if the payload is malformed.
     */
    private String buildDescription(String payloadB64) {
        try {
            // Pad Base64URL to standard Base64 length
            int pad = (4 - payloadB64.length() % 4) % 4;
            String padded = payloadB64 + "=".repeat(pad);
            String payloadJson = new String(Base64.getUrlDecoder().decode(padded));

            // Simple string extraction — no full JSON parser needed here
            String subject = extractClaim(payloadJson, "sub");
            String email   = extractClaim(payloadJson, "email");
            String issuer  = extractClaim(payloadJson, "iss");
            boolean isExpired = isTokenExpired(payloadJson);

            StringBuilder sb = new StringBuilder("JWT detected — live auth token");
            if (isExpired) {
                sb.append(" (Expired)");
            }
            sb.append(".");
            if (!issuer.isEmpty())  sb.append(" Issuer: ").append(issuer).append(".");
            if (!subject.isEmpty()) sb.append(" Subject: ").append(subject).append(".");
            if (!email.isEmpty())   sb.append(" Email: ").append(email).append(".");
            sb.append(" Sending tokens to AI tools exposes user sessions and API access.");
            return sb.toString();

        } catch (Exception e) {
            return "JWT detected — live auth token. Sending tokens to AI exposes user sessions.";
        }
    }

    private String extractClaim(String json, String key) {
        // Looks for  "key":"value",  "key": "value", or "key": 123
        Pattern p = Pattern.compile("\"" + key + "\"\\s*:\\s*\"?([^\",}]+)\"?");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1).trim() : "";
    }

    private boolean isTokenExpired(String payloadJson) {
        String exp = extractClaim(payloadJson, "exp");
        if (!exp.isEmpty()) {
            try {
                long expTime = Long.parseLong(exp) * 1000; // JWT exp is in seconds
                return expTime < System.currentTimeMillis();
            } catch (NumberFormatException e) {
                // Ignore parsing errors and assume not expired
                return false;
            }
        }
        return false;
    }
}
