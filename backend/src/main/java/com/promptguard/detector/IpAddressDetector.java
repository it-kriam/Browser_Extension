package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IpAddressDetector — High-Performance Network Shield.
 * L1: Regex detection for Public IPv4 and IPv6 addresses (private IPs excluded).
 * L2: Semantic intent for network infrastructure detail sharing.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class IpAddressDetector implements Detector {

    // ── L1: IPv4 Pattern ──────────────────────────────────────────────────
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" +
        "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    // ── L1: IPv6 Pattern ──────────────────────────────────────────────────
    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b");

    // ── L2: High-Risk Network Keywords (score=70) ─────────────────────────
    private static final List<String> NETWORK_IDENTITY_KEYWORDS = List.of(
        "ip address", "server ip", "client ip", "public ip", "external ip",
        "production ip", "staging ip", "load balancer ip", "database ip",
        "api server ip", "vpn ip", "proxy ip", "nat gateway ip",
        "elastic ip", "static ip", "floating ip"
    );

    // ── L2: Medium-Risk Infra Keywords (score=55) ─────────────────────────
    private static final List<String> NETWORK_INFRA_KEYWORDS = List.of(
        "ipv4", "ipv6", "network ip", "gateway ip", "subnet mask",
        "cidr", "network range", "ip range", "dns server",
        "nameserver", "reverse dns", "ptr record", "whois",
        "traceroute", "network topology", "vlan", "firewall rule",
        "acl rule", "security group", "network interface", "nic"
    );

    // ── L2: Low-Risk Context Keywords (score=45) ──────────────────────────
    private static final List<String> NETWORK_CONTEXT_KEYWORDS = List.of(
        "port number", "listening on port", "open port", "tcp port",
        "udp port", "ssh to", "rdp to", "connect to host",
        "ping", "network config", "hosts file", "network address"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "IpAddressDetector"; }

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
        Matcher v4Matcher = IPV4_PATTERN.matcher(prompt);
        while (v4Matcher.find()) {
            String ip = v4Matcher.group();
            if (!isPrivateIP(ip)) {
                results.add(new DetectionResult(RiskType.PII, 70,
                    "L1_IP_REGEX: Public IPv4 Address", ip));
                match = true;
            }
        }
        Matcher v6Matcher = IPV6_PATTERN.matcher(prompt);
        while (v6Matcher.find()) {
            results.add(new DetectionResult(RiskType.PII, 65,
                "L1_IP_REGEX: IPv6 Address", v6Matcher.group()));
            match = true;
        }
        return match;
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        boolean isSafetyInquiry = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexCheckOnly(original)) {
            results.add(new DetectionResult(RiskType.PII, 20, "L2_IP_INQUIRY",
                "INFO: User is inquiring about network safety, not disclosing infrastructure."));
            return;
        }

        // Tier 1: Network identity keywords → score 70 (REDACT)
        for (String kw : NETWORK_IDENTITY_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.PII, 70,
                    "L2_IP_IDENTITY: " + kw, kw));
                return;
            }
        }
        // Tier 2: Infrastructure keywords → score 55 (ALERT)
        for (String kw : NETWORK_INFRA_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.PII, 55,
                    "L2_IP_INFRASTRUCTURE: " + kw, kw));
                return;
            }
        }
        // Tier 3: Context keywords → score 45 (ALERT)
        for (String kw : NETWORK_CONTEXT_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.PII, 45,
                    "L2_IP_CONTEXT: " + kw, kw));
                return;
            }
        }
    }

    private boolean runRegexCheckOnly(String prompt) {
        Matcher v4Matcher = IPV4_PATTERN.matcher(prompt);
        while (v4Matcher.find()) {
            if (!isPrivateIP(v4Matcher.group())) return true;
        }
        return IPV6_PATTERN.matcher(prompt).find();
    }

    private boolean isPrivateIP(String ip) {
        return ip.startsWith("10.") || ip.startsWith("172.16.") ||
               ip.startsWith("192.168.") || ip.startsWith("127.") ||
               ip.startsWith("0.");
    }
}
