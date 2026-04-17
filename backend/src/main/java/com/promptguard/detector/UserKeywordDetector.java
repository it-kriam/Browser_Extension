package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.model.UserKeywordPolicy;
import com.promptguard.repository.UserPolicyRepository;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * UserKeywordDetector — High-Performance Org-specific Shield.
 * L1: DB-driven keyword matching per organization (userId + subUser).
 * L2: Semantic intent for organizational policy circumvention and data exfiltration.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class UserKeywordDetector implements Detector {

    private final UserPolicyRepository repository;

    public UserKeywordDetector(UserPolicyRepository repository) {
        this.repository = repository;
    }

    // ── L2: Organizational Data Sharing Keywords ──────────────────────────
    private static final List<String> ORG_SHARING_KEYWORDS = List.of(
        "internal document", "company document", "confidential document",
        "private document", "restricted document", "internal report",
        "board minutes", "meeting notes", "financial report",
        "employee list", "salary data", "performance review"
    );

    private static final List<String> SHARING_ACTIONS = List.of(
        "share", "send", "forward", "distribute", "publish", "post",
        "upload", "attach", "submit", "copy", "paste", "leak",
        "disclose", "reveal", "expose", "broadcast", "transfer"
    );

    private static final List<String> CIRCUMVENTION_KEYWORDS = List.of(
        "work around policy", "bypass policy", "get around restriction",
        "avoid detection", "hide from compliance", "evade filter",
        "rephrase to avoid", "alternative wording", "say it differently",
        "encode to bypass", "obfuscate", "disguise the data"
    );

    private static final java.util.regex.Pattern INQUIRY_PATTERN = java.util.regex.Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        java.util.regex.Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "UserKeywordDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt  = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        String userId  = context.getUserId();
        String subUser = context.getSubUser();
 
        if (prompt == null || prompt.isBlank()) return results;
        if (userId == null || subUser == null)  return results;
 
        // ── LAYER 1: DB-DRIVEN EXACT MATCH (Original + Normalized) ──────
        if (runRegexLayer(userId, subUser, prompt, normalized, results)) return results;
 
        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);
 
        return results;
    }
 
    private boolean runRegexLayer(String userId, String subUser, String prompt, String normalized, List<DetectionResult> results) {
        List<UserKeywordPolicy> policies = repository.findPolicies(userId, subUser);
        String lowerPrompt = prompt.toLowerCase();
        boolean matchFound = false;
 
        for (UserKeywordPolicy policy : policies) {
            String subUserField = policy.getSubUser();
            if (!"*".equals(subUserField) && !subUser.equalsIgnoreCase(subUserField)) continue;
 
            String[] keywords = policy.getKeywordList().split(",");
            for (String kw : keywords) {
                String cleanKw = kw.trim();
                if (cleanKw.isEmpty()) continue;
 
                String lowerKw = cleanKw.toLowerCase();
                String normKw = lowerKw.replace(" ", "").replace("-", "").replace("_", "");
                
                if (cleanKw.equals("*") || lowerPrompt.contains(lowerKw) || normalized.contains(normKw)) {
                    if (policy.isAllowCol()) return false; // Early exit on whitelist
 
                    int score = 0;
                    String actionStr = "NONE";
 
                    if (policy.isBlockCol()) {
                        score = 100;
                        actionStr = "BLOCK";
                    } else if (policy.isCriticalCol()) {
                        score = 55;
                        actionStr = "CRITICAL";
                    } else if (policy.isRedactedCol()) {
                        score = 75;
                        actionStr = "REDACT";
                    }
 
                    if (score > 0) {
                        results.add(new DetectionResult(RiskType.ORG_KEYWORD, score,
                            "L1_ORG_HIT (" + actionStr + ") for org [" + userId + "]: \"" + cleanKw + "\"",
                            cleanKw));
                        matchFound = true;
                    }
                    break;
                }
            }
        }
        return matchFound;
    }
 
    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");
 
        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry) {
            results.add(new DetectionResult(RiskType.ORG_KEYWORD, 20, "L2_ORG_INQUIRY",
                "INFO: User is inquiring about organizational policy, not attempting a bypass."));
            return;
        }
 
        // Check for policy circumvention intent (against normalized)
        boolean hasCircumvention = CIRCUMVENTION_KEYWORDS.stream()
            .anyMatch(kw -> normalized.contains(kw.replace(" ", "")));
            
        if (hasCircumvention) {
            results.add(new DetectionResult(RiskType.ORG_KEYWORD, 85,
                "L2_ORG_CIRCUMVENTION: Policy circumvention attempt detected", original));
            return;
        }
 
        // Check for org data sharing intent
        boolean hasOrgData = ORG_SHARING_KEYWORDS.stream()
            .anyMatch(kw -> normalized.contains(kw.replace(" ", "")));
        boolean hasSharingAction = SHARING_ACTIONS.stream()
            .anyMatch(act -> normalized.contains(act.replace(" ", "")));
 
        if (hasOrgData && hasSharingAction) {
            results.add(new DetectionResult(RiskType.ORG_KEYWORD, 75,
                "L2_ORG_DATA_SHARING: Internal data sharing intent detected", original));
        } else if (hasOrgData) {
            results.add(new DetectionResult(RiskType.ORG_KEYWORD, 55,
                "L2_ORG_DATA_MENTION: Internal data reference detected", original));
        }
    }
}
