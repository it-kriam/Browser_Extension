package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CloudProviderDetector — 3-Layer Intelligent Cloud Shield.
 * L1: Regex detection for Cloud Secrets (AWS/Azure/GCP) and Infrastructure URLs.
 * L2: Semantic intent for infrastructure configuration sharing.
 * L3: LLM reasoning for obfuscated cloud credentials or account takeovers.
 */
@Component
public class CloudProviderDetector implements Detector {

    private static final List<Pattern> CLOUD_SECRET_PATTERNS = List.of(
            Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b"),
            Pattern.compile("\\b[a-zA-Z0-9/+=]{40}\\b"),
            Pattern.compile("sig=[a-zA-Z0-9%]{20,}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\"private_key\"\\s*:\\s*\"-----BEGIN PRIVATE KEY-----\\s*[a-zA-Z0-9/+=\\s]+\\s*-----END PRIVATE KEY-----\"", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
            Pattern.compile("Signature=[a-zA-Z0-9~_-]+", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> CLOUD_INFRA_PATTERNS = List.of(
            Pattern.compile("\\b[a-z0-9.-]+\\.s3(?:[.-]?[a-z0-9-]+)?\\.amazonaws\\.com(?:/[a-z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\b[a-z0-9.-]+\\.blob\\.core\\.windows\\.net(?:/[a-z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bstorage\\.googleapis\\.com/[a-z0-9.-]+(?:/[a-z0-9._-]*)?", Pattern.CASE_INSENSITIVE)
    );

    private static final List<String> CLOUD_KEYWORDS = List.of(
            "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AZURE_STORAGE_KEY", "GCP_CREDENTIALS", "CLOUDFRONT_KEY"
    );

    public CloudProviderDetector() {
    }

    @Override
    public String getName() {
        return "CloudProviderDetector";
    }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        return detect(context.getPrompt(), context.getDecision());
    }

    public List<DetectionResult> detect(String prompt, OllamaService.LlmDecision decision) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX ───────────────────────────────────────────
        if (runRegexLayer(prompt, results)) return results;

        // ── LAYER 2: SEMANTIC ────────────────────────────────────────
        runSemanticLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 3: LLM (Reusing shared decision) ───────────────────
        runLlamaLayer(prompt, results, decision);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        boolean match = false;
        for (Pattern p : CLOUD_SECRET_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 90, "L1_CLOUD: Provider Secret/Key", m.group()));
                match = true;
            }
        }
        for (Pattern p : CLOUD_INFRA_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 65, "L1_CLOUD: Infrastructure URL", m.group()));
                match = true;
            }
        }
        return match;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : CLOUD_KEYWORDS) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 85, "L2_CLOUD_KEYWORD: " + kw, kw));
                return;
            }
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 80 && (decision.reason.toUpperCase().contains("CLOUD") || decision.reason.toUpperCase().contains("AWS") || decision.reason.toUpperCase().contains("AZURE") || decision.reason.toUpperCase().contains("GCP"))) {
            results.add(new DetectionResult(RiskType.SECRET, decision.score, "L3_CLOUD_LLM: " + decision.reason, prompt));
        }
    }
}
