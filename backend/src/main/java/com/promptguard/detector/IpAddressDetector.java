package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class IpAddressDetector {

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
        "ip address", "ipv4", "ipv6", "localhost", "127.0.0.1", 
        "network ip", "client ip", "server ip", "gateway ip", "subnet mask"
    );

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // Detect IPv4 Addresses
        Matcher v4Matcher = IPV4_PATTERN.matcher(prompt);
        while (v4Matcher.find()) {
            String ip = v4Matcher.group();

            // Skip RFC 1918 private ranges (often safe in configs)
            if (!isPrivateIP(ip)) {
                results.add(new DetectionResult(
                        RiskType.PII,
                        70,  // Higher score for public IPs
                        "Public IPv4 Address detected: " + ip,
                        ip
                ));
            }
        }

        // Detect IPv6 Addresses
        Matcher v6Matcher = IPV6_PATTERN.matcher(prompt);
        while (v6Matcher.find()) {
            results.add(new DetectionResult(
                    RiskType.PII,
                    65, 
                    "IPv6 Address detected. Potentially leaking network infrastructure or user location.",
                    v6Matcher.group()
            ));
        }

        // Keyword checks
        checkKeywords(prompt, IP_KEYWORDS, "IP Address Keyword", 55, results);

        return results;
    }

    private void checkKeywords(String prompt, Set<String> keywords, String label,
                                int score, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : keywords) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(
                    RiskType.PII,
                    score,
                    "PII detected: " + label + " — \"" + kw + "\"",
                    kw
                ));
                return; // one hit per category is enough
            }
        }
    }

    private boolean isPrivateIP(String ip) {
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 0.0.0.0/8
        return ip.startsWith("10.") || ip.startsWith("172.16.") || 
               ip.startsWith("192.168.") || ip.startsWith("127.") || 
               ip.startsWith("0.");
    }
}
