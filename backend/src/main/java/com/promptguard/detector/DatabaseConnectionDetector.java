package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DatabaseConnectionDetector — detects database connection strings and credentials.
 * 
 * Score mapping:
 *   Full JDBC/URI with password → score=95 → BLOCK
 *   Database URL/Host/Port      → score=75 → REDACT
 *   Keywords (DB_PASSWORD etc)  → score=80 → BLOCK
 */
@Component
public class DatabaseConnectionDetector {

    private static final List<Pattern> DB_CONNECTION_PATTERNS = List.of(
            // JDBC / Generic Database URLs with password
            Pattern.compile("\\bjdbc:[a-z]+://[^\\s]*password=[^\\s&]+", Pattern.CASE_INSENSITIVE),
            // MongoDB Connection String
            Pattern.compile("mongodb(?:\\+srv)?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            // Redis URL
            Pattern.compile("redis://(?:[a-zA-Z0-9._-]+:)?([a-zA-Z0-9._-]+)@[a-zA-Z0-9.-]+:[0-9]+", Pattern.CASE_INSENSITIVE),
            // Postgres / MySQL standard URI
            Pattern.compile("(?:postgres|postgresql|mysql|mariadb)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:[0-9]+)?(?:/[a-zA-Z0-9._-]*)?", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> DB_URL_ONLY_PATTERNS = List.of(
            // Connection strings without obvious passwords
            Pattern.compile("\\bjdbc:[a-z]+://[a-zA-Z0-9.-]+:[0-9]+(?:/[a-zA-Z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bDATABASE_URL\\s*[=:]\\s*\\S+", Pattern.CASE_INSENSITIVE)
    );

    private static final List<String> DB_KEYWORDS = List.of(
            "DB_PASSWORD", "DATABASE_PASSWORD", "DB_USER", "DATABASE_USERNAME", "DB_CONN_STR"
    );

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // 1. Check for full connection strings with passwords (BLOCK)
        for (Pattern p : DB_CONNECTION_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 95, "Database connection string with credentials detected", m.group()));
            }
        }

        // 2. Check for keywords (BLOCK)
        String lower = prompt.toLowerCase();
        for (String kw : DB_KEYWORDS) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 85, "Database credential keyword detected: " + kw, kw));
            }
        }

        // 3. Check for URLs without passwords (REDACT)
        for (Pattern p : DB_URL_ONLY_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 75, "Database connection URL without credentials detected", m.group()));
            }
        }

        return results;
    }
}
