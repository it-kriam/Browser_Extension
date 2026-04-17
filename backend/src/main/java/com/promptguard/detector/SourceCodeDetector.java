package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SourceCodeDetector — High-Performance Code Shield.
 * L1: Regex detection for Java, SQL, Python, and JavaScript code structures.
 * L2: Semantic intent for proprietary code sharing.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class SourceCodeDetector implements Detector {

    // ── L1: Java Patterns ─────────────────────────────────────────────────
    private static final Pattern JAVA_CLASS = Pattern.compile(
        "\\b(public|private|protected)\\s+(class|interface|enum)\\s+\\w+");
    private static final Pattern JAVA_ANNOTATION = Pattern.compile(
        "@(Autowired|Service|Repository|Controller|RestController|Component|Entity|Bean)");

    // ── L1: SQL Patterns ──────────────────────────────────────────────────
    private static final Pattern SQL_SELECT = Pattern.compile(
        "\\bSELECT\\s+.{1,200}\\s+FROM\\s+\\w+",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern SQL_INSERT = Pattern.compile(
        "\\bINSERT\\s+INTO\\s+\\w+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_UPDATE = Pattern.compile(
        "\\bUPDATE\\s+\\w+\\s+SET\\s+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_DELETE = Pattern.compile(
        "\\bDELETE\\s+FROM\\s+\\w+", Pattern.CASE_INSENSITIVE);

    // ── L1: Python Patterns ───────────────────────────────────────────────
    private static final Pattern PYTHON_DEF = Pattern.compile(
        "^def\\s+\\w+\\s*\\(", Pattern.MULTILINE);
    private static final Pattern PYTHON_CLASS = Pattern.compile(
        "^class\\s+\\w+\\s*[:(]", Pattern.MULTILINE);
    private static final Pattern PYTHON_IMPORT = Pattern.compile(
        "^(?:from\\s+\\w+\\s+)?import\\s+\\w+", Pattern.MULTILINE);

    // ── L1: JavaScript/TypeScript Patterns ────────────────────────────────
    private static final Pattern JS_FUNCTION = Pattern.compile(
        "\\b(?:function|const|let|var)\\s+\\w+\\s*=?\\s*(?:async\\s+)?\\(?");
    private static final Pattern JS_ARROW = Pattern.compile(
        "\\b(?:const|let|var)\\s+\\w+\\s*=\\s*\\(?[^)]*\\)?\\s*=>");

    // ── L2: Code Sharing Keywords ─────────────────────────────────────────
    private static final List<String> CODE_REFERENCE_KEYWORDS = List.of(
        "source code", "codebase", "code snippet", "code block",
        "function", "method", "class", "module", "library",
        "algorithm", "implementation", "logic", "backend code",
        "frontend code", "api endpoint", "controller", "service layer",
        "repository layer", "data model", "schema definition"
    );

    private static final List<String> CODE_SHARING_INTENT = List.of(
        "here is", "fix this", "debug this", "review this", "check this",
        "run this", "execute this", "optimize this", "refactor this",
        "here is my code", "review my code", "what's wrong with",
        "can you fix", "help me with this code", "look at this code",
        "analyze this code", "improve this", "convert this code"
    );

    private static final List<String> PROPRIETARY_KEYWORDS = List.of(
        "proprietary", "internal", "company code", "production code",
        "trade secret", "confidential code", "private repository",
        "our codebase", "our api", "our backend", "our service",
        "do not share", "not open source", "licensed code"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "SourceCodeDetector"; }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        List<DetectionResult> results = new ArrayList<>();
        String prompt = context.getPrompt();
        String normalized = context.getNormalizedPrompt();
        
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX (Original Text — Short-circuits) ────────────────
        runRegexLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 2: SEMANTIC (Normalized Text) ───────────────────────────
        runSemanticLayer(prompt, normalized, results);

        return results;
    }

    private void runRegexLayer(String prompt, List<DetectionResult> results) {
        if (JAVA_CLASS.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 70,
                "L1_CODE_REGEX: Java Class/Interface", snippet(prompt, JAVA_CLASS)));
        }
        if (JAVA_ANNOTATION.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 60,
                "L1_CODE_REGEX: Spring Annotation", snippet(prompt, JAVA_ANNOTATION)));
        }
        if (SQL_SELECT.matcher(prompt).find() || SQL_INSERT.matcher(prompt).find()
            || SQL_UPDATE.matcher(prompt).find() || SQL_DELETE.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 55,
                "L1_CODE_REGEX: SQL Query", "SQL detected"));
        }
        if (PYTHON_DEF.matcher(prompt).find() || PYTHON_CLASS.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 50,
                "L1_CODE_REGEX: Python Code", snippet(prompt, PYTHON_DEF)));
        }
        if (PYTHON_IMPORT.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 45,
                "L1_CODE_REGEX: Python Import", snippet(prompt, PYTHON_IMPORT)));
        }
        if (JS_FUNCTION.matcher(prompt).find() || JS_ARROW.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 50,
                "L1_CODE_REGEX: JavaScript/TypeScript Code", "JS/TS detected"));
        }
    }

    private void runSemanticLayer(String original, String normalized, List<DetectionResult> results) {
        String lowerOrig = original.toLowerCase();
        
        boolean hasCodeRef      = CODE_REFERENCE_KEYWORDS.stream().anyMatch(normalized::contains);
        boolean hasSharingIntent = CODE_SHARING_INTENT.stream().anyMatch(normalized::contains);
        boolean hasProprietary   = PROPRIETARY_KEYWORDS.stream().anyMatch(normalized::contains);
        boolean isSafetyInquiry  = INQUIRY_PATTERN.matcher(normalized).find() || lowerOrig.contains("?");

        // Inquiry logic: Questions about safety should be ALLOW (low score)
        if (isSafetyInquiry && !runRegexCheckOnly(original)) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 20, "L2_CODE_INQUIRY",
                "INFO: User is inquiring about code safety, not disclosing proprietary source."));
            return;
        }

        if (hasCodeRef && hasSharingIntent && hasProprietary) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 85,
                "L2_CODE_PROPRIETARY_INTENT",
                "CRITICAL: Proprietary code sharing attempt detected."));
        } else if (hasCodeRef && hasSharingIntent) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 65,
                "L2_CODE_SHARING_INTENT",
                "WARNING: Code sharing intent detected."));
        } else if (hasProprietary) {
            // Changed from 55 to 45 for consistency
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 45,
                "L2_CODE_PROPRIETARY_MENTION",
                "INFO: Proprietary code reference detected."));
        }
    }

    private boolean runRegexCheckOnly(String prompt) {
        return JAVA_CLASS.matcher(prompt).find() || JAVA_ANNOTATION.matcher(prompt).find() ||
               SQL_SELECT.matcher(prompt).find() || SQL_INSERT.matcher(prompt).find() ||
               SQL_UPDATE.matcher(prompt).find() || SQL_DELETE.matcher(prompt).find() ||
               PYTHON_DEF.matcher(prompt).find() || PYTHON_CLASS.matcher(prompt).find() ||
               PYTHON_IMPORT.matcher(prompt).find() || JS_FUNCTION.matcher(prompt).find() ||
               JS_ARROW.matcher(prompt).find();
    }

    private String snippet(String text, Pattern p) {
        Matcher m = p.matcher(text);
        if (m.find()) {
            String match = m.group();
            return match.substring(0, Math.min(60, match.length()));
        }
        return "";
    }
}
