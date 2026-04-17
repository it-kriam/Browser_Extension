package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PhiDetector — High-Performance Medical Shield (PHI / HIPAA).
 * L1: Fast Regex Matching (MRN, ICD-10, NPI, Date of Birth).
 * L2: Semantic Intent Analysis — detects medical disclosure intent even without coded data.
 * Both layers always run — L2 catches intent cases L1 misses entirely.
 */
@Component
public class PhiDetector implements Detector {

    // ── L1: Structural Regex Patterns ─────────────────────────────────────
    private static final Pattern MRN   = Pattern.compile(
        "\\b(MRN|mrn|medical record|patient id|patient#|record number)[:\\s#-]*[A-Z0-9]{4,15}\\b",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern ICD10 = Pattern.compile(
        "\\b[A-Z][0-9]{2}(\\.?[A-Z0-9]{1,6})?\\b");
    private static final Pattern NPI   = Pattern.compile(
        "\\b(NPI|npi)[:\\s#-]*\\d{10}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOB   = Pattern.compile(
        "\\b(dob|date of birth|born on)[:\\s]*(\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4})",
        Pattern.CASE_INSENSITIVE);

    // ── L2: Semantic Keywords (plain contains — fast and safe) ────────────
    private static final List<String> PERSONAL_CONTEXT = List.of(
        "my", "me", "i am", "he has", "she was", "their", "his", "her",
        "patient", "the patient", "my patient", "our patient", "this patient"
    );

    private static final List<String> HEALTH_CONTEXT = List.of(
        "diagnosed", "prescribed", "treatment", "symptoms", "surgery", "patient",
        "history", "condition", "medication", "allergy", "lab result", "test result",
        "blood type", "medical record", "health record", "insurance", "hospital",
        "clinic", "doctor", "physician", "nurse", "cancer", "diabetes", "hiv",
        "mental health", "disability", "immunization", "vaccine", "chronic",
        "prognosis", "biopsy", "radiology", "pathology", "prescription",
        "discharge summary", "admission", "emergency", "icu", "dose", "therapy"
    );

    private static final List<String> DISCLOSURE_WORDS = List.of(
        "sharing", "sending", "giving", "here is", "attached", "review",
        "update", "store", "save", "submit", "upload", "disclose", "provide",
        "forwarding", "pass this", "use this", "here are the records"
    );

    @Override
    public String getName() { return "PhiDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX (Original Text) ────────────────────────────────
        runRegexLayer(prompt, results);

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(normalized, results);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        boolean match = false;
        match |= checkPattern(prompt, MRN,   "MRN (Medical Record Number)", 75, results);
        match |= checkPattern(prompt, ICD10, "ICD-10 Code",                 80, results);
        match |= checkPattern(prompt, NPI,   "NPI (Provider Identifier)",   75, results);
        match |= checkPattern(prompt, DOB,   "Date of Birth",               75, results);
        return match;
    }

    private void runSemanticLayer(String normalized, List<DetectionResult> results) {
        boolean hasPersonal   = PERSONAL_CONTEXT.stream().anyMatch(normalized::contains);
        boolean hasHealth     = HEALTH_CONTEXT.stream().anyMatch(normalized::contains);
        boolean hasDisclosure = DISCLOSURE_WORDS.stream().anyMatch(normalized::contains);

        if (hasPersonal && hasHealth && hasDisclosure) {
            // All 3 signals: personal context + health data + active sharing → BLOCK (score ≥ 80)
            results.add(new DetectionResult(RiskType.PHI, 90, "L2_PHI_FULL_INTENT",
                "CRITICAL: High-confidence PHI sharing intent detected."));
        } else if (hasPersonal && hasHealth) {
            // Personal medical context without active sharing → REDACT (60-79)
            results.add(new DetectionResult(RiskType.PHI, 70, "L2_PHI_PARTIAL_INTENT",
                "WARNING: Personal medical condition detected in prompt."));
        } else if (hasHealth) {
            // Health topic mentioned without personal ownership → ALERT (40-59)
            results.add(new DetectionResult(RiskType.PHI, 50, "L2_PHI_HEALTH_MENTION",
                "INFO: Health-related topic referenced in prompt."));
        }
    }

    private boolean checkPattern(String prompt, Pattern p, String label, int score, List<DetectionResult> results) {
        Matcher m = p.matcher(prompt);
        if (m.find()) {
            results.add(new DetectionResult(RiskType.PHI, score, "L1_PHI_EXACT: " + label, m.group()));
            return true;
        }
        return false;
    }
}
