package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * JailbreakDetector — The Final Shield.
 * Specifically uses Llama3 (Ollama) to detect 'Prompt Injections' and
 * 'Jailbreak' attempts.
 * This looks for 'Persona playing', 'Rule-bypassing', and 'Instruction
 * override' intent.
 */
@Component
public class JailbreakDetector {

    private final OllamaService ollamaService;

    public JailbreakDetector(OllamaService ollamaService) {
        this.ollamaService = ollamaService;
    }

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank())
            return results;

        // CALL THE REAL OLLAMA SERVICE (High Priority Firewall)
        OllamaService.LlmDecision decision = ollamaService.predictRisk(prompt);

        // If Llama3 detects a "BLOCK" action with high score, it's a Jailbreak
        if ("BLOCK".equals(decision.action) && decision.score >= 85) {
            results.add(new DetectionResult(
                    RiskType.PROMPT_INJECTION,
                    decision.score,
                    "L3_OLLAMA_JAILBREAK: " + decision.reason,
                    prompt));
        }

        return results;
    }
}
