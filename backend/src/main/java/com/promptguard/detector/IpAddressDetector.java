package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IpAddressDetector — 3-Layer Intelligent Network Shield.
 * L1: Regex detection for Public IPv4 and IPv6 addresses.
 * L2: Semantic intent for infrastructure detail sharing.
 * L3: LLM reasoning for hidden network topologies or leaks.
 */
@Component
public class IpAddressDetector implements Detector {

    // IPv4 Address Pattern (e.g. 192.168.1.1)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"
    );

    // Simplified IPv6 Address Pattern (e.g. 2001:0db8:85a3:0000:0000:8a2e:0370:7334)
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b"
    );

    // Common IP-related keywords
    private static final Set<String> IP_KEYWORDS = Set.of(
        "ip address", "ipv4", "ipv6", "network ip", "client ip", "server ip", "gateway ip", "subnet mask"
    );

    public IpAddressDetector() {
    }

    @Override
    public String getName() {
        return "IpAddressDetector";
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
        Matcher v4Matcher = IPV4_PATTERN.matcher(prompt);
        while (v4Matcher.find()) {
            String ip = v4Matcher.group();
            if (!isPrivateIP(ip)) {
                results.add(new DetectionResult(RiskType.PII, 70, "L1_IP: Public IPv4 Address", ip));
                match = true;
            }
        }
        Matcher v6Matcher = IPV6_PATTERN.matcher(prompt);
        while (v6Matcher.find()) {
            results.add(new DetectionResult(RiskType.PII, 65, "L1_IP: IPv6 Address", v6Matcher.group()));
            match = true;
        }
        return match;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : IP_KEYWORDS) {
            if (lower.contains(kw)) {
                results.add(new DetectionResult(RiskType.PII, 55, "L2_IP_KEYWORD: " + kw, kw));
                return;
            }
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 70 && (decision.reason.toUpperCase().contains("IP ADDRESS") || decision.reason.toUpperCase().contains("NETWORK"))) {
            results.add(new DetectionResult(RiskType.PII, decision.score, "L3_IP_LLM: " + decision.reason, prompt));
        }
    }

    private boolean isPrivateIP(String ip) {
        return ip.startsWith("10.") || ip.startsWith("172.16.") || 
               ip.startsWith("192.168.") || ip.startsWith("127.") || 
               ip.startsWith("0.");
    }
}
