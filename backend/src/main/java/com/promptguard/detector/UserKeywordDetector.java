package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.model.UserKeywordPolicy;
import com.promptguard.repository.UserPolicyRepository;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * UserKeywordDetector — 3-Layer Intelligent Org-specific Shield.
 * L1: Isolated keyword matching from Database.
 * L2: Semantic intent for organizational policy circumvention.
 * L3: LLM reasoning for proprietary data leaks within org context.
 */
@Component
public class UserKeywordDetector implements Detector {

    private final UserPolicyRepository repository;

    public UserKeywordDetector(UserPolicyRepository repository) {
        this.repository = repository;
    }

    @Override
    public String getName() {
        return "UserKeywordDetector";
    }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        return detect(context.getUserId(), context.getSubUser(), context.getPrompt(), context.getDecision());
    }

    public List<DetectionResult> detect(String userId, String subUser, String prompt, OllamaService.LlmDecision decision) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;
        if (userId == null || subUser == null)  return results;

        // ── LAYER 1: REGEX / EXACT (DB Managed) ─────────────────────
        if (runRegexLayer(userId, subUser, prompt, results)) return results;

        // ── LAYER 2: SEMANTIC ────────────────────────────────────────
        runSemanticLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 3: LLM (Reusing shared decision) ───────────────────
        runLlamaLayer(userId, prompt, results, decision);

        return results;
    }

    private boolean runRegexLayer(String userId, String subUser, String prompt, List<DetectionResult> results) {
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

                if (cleanKw.equals("*") || lowerPrompt.contains(cleanKw.toLowerCase())) {
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
                            "L1_ORG_HIT (" + actionStr + ") for org [" + userId + "]: \"" + cleanKw + "\"", cleanKw));
                        matchFound = true;
                    }
                    break; 
                }
            }
        }
        return matchFound;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        if (lower.contains("internal") && lower.contains("document") && lower.contains("share")) {
            results.add(new DetectionResult(RiskType.ORG_KEYWORD, 65, "L2_ORG_INTENT: Internal document sharing attempt", prompt));
        }
    }

    private void runLlamaLayer(String orgId, String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 80 && (decision.reason.toUpperCase().contains("CONFIDENTIAL") || decision.reason.toUpperCase().contains("INTERNAL"))) {
            results.add(new DetectionResult(RiskType.ORG_KEYWORD, decision.score, "L3_ORG_LLM: " + decision.reason + " (Org: " + orgId + ")", prompt));
        }
    }
}
