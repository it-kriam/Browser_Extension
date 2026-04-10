package com.promptguard.detector;

import com.promptguard.service.OllamaService;

/**
 * DetectionContext — Carries all necessary data for security tools.
 */
public class DetectionContext {
    private final String prompt;
    private final String userId;
    private final String subUser;
    private final OllamaService.LlmDecision decision;

    public DetectionContext(String prompt, String userId, String subUser, OllamaService.LlmDecision decision) {
        this.prompt = prompt;
        this.userId = userId;
        this.subUser = subUser;
        this.decision = decision;
    }

    public String getPrompt() { return prompt; }
    public String getUserId() { return userId; }
    public String getSubUser() { return subUser; }
    public OllamaService.LlmDecision getDecision() { return decision; }
}
