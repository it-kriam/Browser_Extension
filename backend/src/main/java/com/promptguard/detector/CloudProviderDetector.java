package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CloudProviderDetector — High-Performance Cloud Shield.
 * L1: Regex detection for Cloud Secrets (AWS/Azure/GCP) and Infrastructure URLs.
 * L2: Semantic intent for cloud credential and infrastructure config sharing.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class CloudProviderDetector implements Detector {

    // ── L1: Cloud Secret Patterns ─────────────────────────────────────────
    private static final List<Pattern> CLOUD_SECRET_PATTERNS = List.of(
        Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b"),
        Pattern.compile("\\b[a-zA-Z0-9/+=]{40}\\b"),
        Pattern.compile("sig=[a-zA-Z0-9%]{20,}", Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "\"private_key\"\\s*:\\s*\"-----BEGIN PRIVATE KEY-----\\s*[a-zA-Z0-9/+=\\s]+\\s*-----END PRIVATE KEY-----\"",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
        Pattern.compile("Signature=[a-zA-Z0-9~_-]+", Pattern.CASE_INSENSITIVE)
    );

    // ── L1: Cloud Infrastructure URL Patterns ────────────────────────────
    private static final List<Pattern> CLOUD_INFRA_PATTERNS = List.of(
        Pattern.compile(
            "\\b[a-z0-9.-]+\\.s3(?:[.-]?[a-z0-9-]+)?\\.amazonaws\\.com(?:/[a-z0-9._-]*)?",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "\\b[a-z0-9.-]+\\.blob\\.core\\.windows\\.net(?:/[a-z0-9._-]*)?",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "\\bstorage\\.googleapis\\.com/[a-z0-9.-]+(?:/[a-z0-9._-]*)?",
            Pattern.CASE_INSENSITIVE)
    );

    // ── L2: Cloud Credential Keywords ────────────────────────────────────
    private static final List<String> CLOUD_SECRET_KEYWORDS = List.of(
        "aws_secret_access_key", "aws_access_key_id", "azure_storage_key",
        "gcp_credentials", "cloudfront_key", "aws_session_token",
        "azure_client_secret", "google_application_credentials",
        "service_account_key", "iam_role", "cloud_api_key",
        "aws_default_region", "azure_subscription_id", "gcp_project_id"
    );

    // ── L2: Cloud Infrastructure Intent Keywords ──────────────────────────
    private static final List<String> CLOUD_INFRA_KEYWORDS = List.of(
        "deploy to aws", "push to s3", "upload to azure", "gcp bucket",
        "cloud config", "terraform config", "kubectl config", "kube config",
        "ecs cluster", "lambda function", "cloud run", "gke cluster",
        "s3 bucket", "blob storage", "cloud storage", "ec2 instance",
        "azure vm", "cloud function", "container registry", "artifact registry"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "CloudProviderDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX (Original Text — Short-circuits) ────────────────
        if (runRegexLayer(prompt, results)) return results;

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private boolean runRegexLayer(String prompt, List<DetectionResult> results) {
        boolean match = false;
        for (Pattern p : CLOUD_SECRET_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 90,
                    "L1_CLOUD_REGEX: Provider Secret/Key", m.group()));
                match = true;
            }
        }
        for (Pattern p : CLOUD_INFRA_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 65,
                    "L1_CLOUD_REGEX: Infrastructure URL", m.group()));
                match = true;
            }
        }
        return match;
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexLayer(original, new ArrayList<>())) {
            results.add(new DetectionResult(RiskType.SECRET, 20, "L2_CLOUD_INQUIRY",
                "INFO: User is inquiring about cloud safety, not disclosing credentials."));
            return;
        }

        // Tier 1: Cloud credential keyword names mentioned → REDACT (60-79)
        // (Real key values are caught by L1 regex at score=90)
        for (String kw : CLOUD_SECRET_KEYWORDS) {
            if (normalized.contains(kw.replace("_", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 70,
                    "L2_CLOUD_SECRET_KEYWORD: " + kw, kw));
                return;
            }
        }
        // Tier 2: Cloud infra references → ALERT (40-59)
        for (String kw : CLOUD_INFRA_KEYWORDS) {
            if (normalized.contains(kw.replace(" ", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 55,
                    "L2_CLOUD_INFRA_KEYWORD: " + kw, kw));
                return;
            }
        }
    }
}
