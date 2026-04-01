package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CloudProviderDetector — detects cloud infrastructure keys and tokens.
 * 
 * Score mapping:
 *   AWS Secret Access Keys     → score=100 → BLOCK
 *   Azure SAS / Signed URLs    → score=85  → BLOCK
 *   GCP Service Account JSON   → score=95  → BLOCK
 *   S3 Bucket / Global URLs    → score=65  → REDACT
 */
@Component
public class CloudProviderDetector {

    private static final List<Pattern> CLOUD_SECRET_PATTERNS = List.of(
            // AWS Access Key ID
            Pattern.compile("\\bAKIA[0-9A-Z]{16}\\b"),
            // AWS Secret Access Key
            Pattern.compile("\\b[a-zA-Z0-9/+=]{40}\\b"),
            // Azure SAS token
            Pattern.compile("sig=[a-zA-Z0-9%]{20,}", Pattern.CASE_INSENSITIVE),
            // GCP Private Key (from service account JSON marker)
            Pattern.compile("\"private_key\"\\s*:\\s*\"-----BEGIN PRIVATE KEY-----\\s*[a-zA-Z0-9/+=\\s]+\\s*-----END PRIVATE KEY-----\"", Pattern.CASE_INSENSITIVE | Pattern.DOTALL),
            // CloudFront Signed URL signature
            Pattern.compile("Signature=[a-zA-Z0-9~_-]+", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> CLOUD_INFRA_PATTERNS = List.of(
            // S3 Bucket URL (publicly identifiable)
            Pattern.compile("\\b[a-z0-9.-]+\\.s3(?:[.-]?[a-z0-9-]+)?\\.amazonaws\\.com(?:/[a-z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            // Azure Blob storage URL
            Pattern.compile("\\b[a-z0-9.-]+\\.blob\\.core\\.windows\\.net(?:/[a-z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            // GCP Storage URL
            Pattern.compile("\\bstorage\\.googleapis\\.com/[a-z0-9.-]+(?:/[a-z0-9._-]*)?", Pattern.CASE_INSENSITIVE)
    );

    private static final List<String> CLOUD_KEYWORDS = List.of(
            "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AZURE_STORAGE_KEY", "GCP_CREDENTIALS", "CLOUDFRONT_KEY"
    );

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // 1. Check for Cloud Secrets (BLOCK)
        for (Pattern p : CLOUD_SECRET_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 90, "Cloud provider secret/access key detected", m.group()));
            }
        }

        // 2. Check for Cloud Infrastructure URL with identifying info (REDACT)
        for (Pattern p : CLOUD_INFRA_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 65, "Cloud infrastructure resource URL detected", m.group()));
            }
        }

        // 3. Check for keywords (BLOCK)
        String lower = prompt.toLowerCase();
        for (String kw : CLOUD_KEYWORDS) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 85, "Cloud credential keyword detected: " + kw, kw));
            }
        }

        return results;
    }
}
