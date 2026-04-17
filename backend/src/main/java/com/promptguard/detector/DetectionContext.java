package com.promptguard.detector;

/**
 * DetectionContext — Carries all necessary data for security tools.
 * Optimized for speed: LLM Decision removed.
 */
public class DetectionContext {
    private final String prompt;
    private final String normalizedPrompt;
    private final String userId;
    private final String subUser;

    public DetectionContext(String prompt, String normalizedPrompt, String userId, String subUser) {
        this.prompt = prompt;
        this.normalizedPrompt = normalizedPrompt;
        this.userId = userId;
        this.subUser = subUser;
    }

    public String getPrompt() { return prompt; }
    public String getNormalizedPrompt() { return normalizedPrompt; }
    public String getUserId() { return userId; }
    public String getSubUser() { return subUser; }
}
