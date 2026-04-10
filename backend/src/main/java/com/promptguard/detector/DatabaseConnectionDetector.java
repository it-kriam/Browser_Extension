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
 * DatabaseConnectionDetector — 3-Layer Intelligent Database Shield.
 * L1: Regex detection for JDBC, MongoDB, Redis, and SQL connection URIs.
 * L2: Semantic intent for database architecture leaks.
 * L3: LLM reasoning for suspicious database queries or connection attempts.
 */
@Component
public class DatabaseConnectionDetector implements Detector {

    private static final List<Pattern> DB_CONNECTION_PATTERNS = List.of(
            Pattern.compile("\\bjdbc:[a-z]+://[^\\s]*password=[^\\s&]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mongodb(?:\\+srv)?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("redis://(?:[a-zA-Z0-9._-]+:)?([a-zA-Z0-9._-]+)@[a-zA-Z0-9.-]+:[0-9]+", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:postgres|postgresql|mysql|mariadb)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:[0-9]+)?(?:/[a-zA-Z0-9._-]*)?", Pattern.CASE_INSENSITIVE)
    );

    private static final List<Pattern> DB_URL_ONLY_PATTERNS = List.of(
            Pattern.compile("\\bjdbc:[a-z]+://[a-zA-Z0-9.-]+:[0-9]+(?:/[a-zA-Z0-9._-]*)?", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bDATABASE_URL\\s*[=:]\\s*\\S+", Pattern.CASE_INSENSITIVE)
    );

    private static final List<String> DB_KEYWORDS = List.of(
            "DB_PASSWORD", "DATABASE_PASSWORD", "DB_USER", "DATABASE_USERNAME", "DB_CONN_STR"
    );

    public DatabaseConnectionDetector() {
    }

    @Override
    public String getName() {
        return "DatabaseConnectionDetector";
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
        for (Pattern p : DB_CONNECTION_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 95, "L1_DB: Connection String with Credentials", m.group()));
                match = true;
            }
        }
        for (Pattern p : DB_URL_ONLY_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 75, "L1_DB: Connection URL", m.group()));
                match = true;
            }
        }
        return match;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : DB_KEYWORDS) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 85, "L2_DB_KEYWORD: " + kw, kw));
                return;
            }
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 80 && (decision.reason.toUpperCase().contains("DATABASE") || decision.reason.toUpperCase().contains("CONNECTION") || decision.reason.toUpperCase().contains("SQL"))) {
            results.add(new DetectionResult(RiskType.SECRET, decision.score, "L3_DB_LLM: " + decision.reason, prompt));
        }
    }
}
