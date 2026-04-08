package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PhiDetector — Fast Medical Shield.
 */
@Component
public class PhiDetector {

    private static final Pattern MRN = Pattern.compile("\\b(MRN|mrn|medical record|patient id|patient#|record number)[:\\s#-]*[A-Z0-9]{4,15}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern ICD10 = Pattern.compile("\\b[A-Z][0-9]{2}(\\.?[A-Z0-9]{1,6})?\\b");
    private static final Pattern NPI = Pattern.compile("\\b(NPI|npi)[:\\s#-]*\\d{10}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern DOB = Pattern.compile("\\b(dob|date of birth|born on)[:\\s]*(\\d{1,2}[/-]\\d{1,2}[/-]\\d{2,4})", Pattern.CASE_INSENSITIVE);

    private static final List<String> HEALTH_CONTEXT = Arrays.asList("diagnosed", "prescribed", "treatment", "symptoms", "surgery", "patient", "history");
    private static final List<String> PERSONAL_CONTEXT = Arrays.asList("my", "me", "i am", "he has", "she was");

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;
        if (runRegexLayer(prompt, results)) return results;
        runSemanticLayer(prompt, results);
        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        boolean match = false;
        match |= checkPattern(prompt, MRN, "MRN (Medical Record Number)", 85, results);
        match |= checkPattern(prompt, ICD10, "ICD-10 code", 85, results);
        match |= checkPattern(prompt, NPI, "NPI", 85, results);
        match |= checkPattern(prompt, DOB, "Date of birth", 75, results);
        return match;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        boolean hasPersonal = PERSONAL_CONTEXT.stream().anyMatch(w -> lower.matches(".*\\b" + w + "\\b.*"));
        boolean hasHealth = HEALTH_CONTEXT.stream().anyMatch(w -> lower.matches(".*\\b" + w + "\\b.*"));
        if (hasPersonal && hasHealth) {
            results.add(new DetectionResult(RiskType.PHI, 70, "L2_PHI_INTENT", prompt));
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
