package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PiiDetector — High-Performance PII Shield.
 * L1: Fast Regex Matching (Email, Phone, Aadhaar, PAN, SSN, Credit Card).
 * L2: Semantic Intent Analysis — detects sharing intent even without raw PII data.
 * Both layers always run — L2 can escalate score (75 REDACT → 90 BLOCK).
 */
@Component
public class PiiDetector implements Detector {

    // ── L1: Structural Regex Patterns ─────────────────────────────────────
    private static final Pattern EMAIL   = Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");
    private static final Pattern PHONE   = Pattern.compile("(\\+91[\\-\\s]?)?[6-9]\\d{9}");
    private static final Pattern AADHAAR = Pattern.compile("\\b[2-9]\\d{3}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}\\b");
    private static final Pattern PAN     = Pattern.compile("\\b[A-Z]{5}[0-9]{4}[A-Z]\\b");
    private static final Pattern SSN     = Pattern.compile("\\b\\d{3}[\\s\\-]?\\d{2}[\\s\\-]?\\d{4}\\b");
    private static final Pattern CREDIT  = Pattern.compile(
        "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}" +
        "|6(?:011|5[0-9]{2})[0-9]{12}|(?:\\d[ -]?){13,19})\\b");

    // ── L2: Semantic Intent Patterns (pre-compiled — no runtime compilation) ──
    private static final Pattern POSSESSION_PATTERN   = Pattern.compile(
        "\\b(my|our|i|me|his|her|their|your)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern SHARING_PATTERN      = Pattern.compile(
        "\\b(is|are|here is|giving|sending|take|provide|attached|sharing|submit|disclosing|here are|use this)\\b",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe)\\b",
        Pattern.CASE_INSENSITIVE);

    private static final List<String> SENSITIVE_WORDS = List.of(
        "password", "login", "api key", "card", "bank", "account", "otp",
        "aadhaar", "pan", "ssn", "social security", "credit card", "debit card",
        "email", "phone", "mobile", "identity", "voter id", "passport", "license",
        "date of birth", "dob", "address", "zip code", "pin code", "account number",
        "ifsc", "routing number", "national id", "driving license"
    );

    @Override
    public String getName() { return "PiiDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX (Original Text) ────────────────────────────────
        runRegexLayer(prompt, results);

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        boolean match = false;
        match |= checkAndAdd(prompt, EMAIL,   "EMAIL",       60, results);
        match |= checkAndAdd(prompt, PHONE,   "PHONE",       65, results);
        match |= checkAndAdd(prompt, AADHAAR, "AADHAAR",     70, results);
        match |= checkAndAdd(prompt, PAN,     "PAN",         70, results);
        match |= checkAndAdd(prompt, SSN,     "SSN",         75, results);
        match |= checkAndAdd(prompt, CREDIT,  "CREDIT_CARD", 75, results);
        return match;
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        
        boolean hasPossession    = POSSESSION_PATTERN.matcher(normalized).find();
        boolean hasSensitive     = SENSITIVE_WORDS.stream().anyMatch(normalized::contains);
        boolean hasSharingIntent = SHARING_PATTERN.matcher(normalized).find();
        boolean isSafetyInquiry  = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexLayer(original, new ArrayList<>())) {
            results.add(new DetectionResult(RiskType.PII, 20, "L2_PII_INQUIRY",
                "INFO: User is inquiring about PII safety, not disclosing it."));
            return;
        }

        if (hasPossession && hasSensitive && hasSharingIntent) {
            // All 3 signals: ownership + sensitive topic + active sharing → BLOCK (≥80)
            results.add(new DetectionResult(RiskType.PII, 80, "L2_PII_FULL_INTENT",
                "HIGH: High-confidence PII sharing intent detected."));
        } else if ((hasPossession && hasSensitive) || (hasSensitive && hasSharingIntent)) {
            // 2 of 3 signals → ALERT (40-59)
            results.add(new DetectionResult(RiskType.PII, 50, "L2_PII_PARTIAL_INTENT",
                "WARNING: Potential PII disclosure pattern detected."));
        } else if (hasSensitive) {
            // Sensitive topic mentioned alone → ALLOW (safe informational)
            results.add(new DetectionResult(RiskType.PII, 30, "L2_PII_SENSITIVE_MENTION",
                "INFO: Sensitive PII topic referenced in prompt."));
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
