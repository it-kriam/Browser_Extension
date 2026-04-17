package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DatabaseConnectionDetector — High-Performance Database Shield.
 * L1: Regex detection for JDBC, MongoDB, Redis, and SQL connection URIs.
 * L2: Semantic intent for database credential/architecture leaks.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class DatabaseConnectionDetector implements Detector {

    // ── L1: Connection Strings WITH Credentials ───────────────────────────
    private static final List<Pattern> DB_CONNECTION_PATTERNS = List.of(
        Pattern.compile("\\bjdbc:[a-z]+://[^\\s]*password=[^\\s&]+", Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "mongodb(?:\\+srv)?://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]*)?",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "redis://(?:[a-zA-Z0-9._-]+:)?([a-zA-Z0-9._-]+)@[a-zA-Z0-9.-]+:[0-9]+",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile(
            "(?:postgres|postgresql|mysql|mariadb)://[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+(?:[0-9]+)?(?:/[a-zA-Z0-9._-]*)?",
            Pattern.CASE_INSENSITIVE)
    );

    // ── L1: Connection URLs WITHOUT Credentials (lower risk) ──────────────
    private static final List<Pattern> DB_URL_ONLY_PATTERNS = List.of(
        Pattern.compile(
            "\\bjdbc:[a-z]+://[a-zA-Z0-9.-]+:[0-9]+(?:/[a-zA-Z0-9._-]*)*",
            Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bDATABASE_URL\\s*[=:]\\s*\\S+", Pattern.CASE_INSENSITIVE)
    );

    // ── L2: High-Risk DB Credential Keywords (score=85) ───────────────────
    private static final List<String> DB_CREDENTIAL_KEYWORDS = List.of(
        "db_password", "database_password", "db_user", "database_username",
        "db_conn_str", "db_secret", "database_credentials", "db_master_password",
        "rds_password", "aurora_password", "root_password", "admin_password",
        "mysql_root_password", "postgres_password", "mongo_password",
        "redis_password", "db_connection_string", "connection_string"
    );

    // ── L2: Medium-Risk DB Architecture Keywords (score=65) ───────────────
    private static final List<String> DB_ARCHITECTURE_KEYWORDS = List.of(
        "database host", "database port", "database name", "schema name",
        "table structure", "column names", "primary key", "foreign key",
        "db migration", "database backup", "rds instance", "rds endpoint",
        "aurora cluster", "replica set", "sharding key", "replication config",
        "database schema", "data model", "entity relationship", "db dump"
    );

    // ── L2: Low-Risk DB Operation Keywords (score=50) ─────────────────────
    private static final List<String> DB_OPERATION_KEYWORDS = List.of(
        "database config", "db config", "spring datasource", "hibernate config",
        "connection pool", "max connections", "idle timeout", "db driver",
        "orm mapping", "entity mapping", "jpa config", "sequelize config"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "DatabaseConnectionDetector"; }

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
        for (Pattern p : DB_CONNECTION_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 95,
                    "L1_DB_REGEX: Connection String with Credentials", m.group()));
                match = true;
            }
        }
        for (Pattern p : DB_URL_ONLY_PATTERNS) {
            Matcher m = p.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 75,
                    "L1_DB_REGEX: Connection URL", m.group()));
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
            results.add(new DetectionResult(RiskType.SECRET, 20, "L2_DB_INQUIRY",
                "INFO: User is inquiring about database safety, not disclosing connection strings."));
            return;
        }

        // Tier 1: Credential field names mentioned → REDACT (60-79)
        // (Real connection strings with passwords caught by L1 at 95)
        for (String kw : DB_CREDENTIAL_KEYWORDS) {
            String cleanKw = kw.replace("_", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.SECRET, 70,
                    "L2_DB_CREDENTIAL: " + kw, kw));
                return;
            }
        }
        // Tier 2: DB architecture detail → ALERT (40-59)
        for (String kw : DB_ARCHITECTURE_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.SECRET, 55,
                    "L2_DB_ARCHITECTURE: " + kw, kw));
                return;
            }
        }
        // Tier 3: DB operational config → ALERT (40-59)
        for (String kw : DB_OPERATION_KEYWORDS) {
            String cleanKw = kw.replace(" ", "").toLowerCase();
            if (normalized.contains(cleanKw)) {
                results.add(new DetectionResult(RiskType.SECRET, 45,
                    "L2_DB_OPERATION: " + kw, kw));
                return;
            }
        }
    }
}
