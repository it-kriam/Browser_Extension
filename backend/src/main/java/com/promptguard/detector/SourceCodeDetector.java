package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import com.promptguard.service.OllamaService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SourceCodeDetector — 3-Layer Intelligent Code Shield.
 * L1: Regex detection for SQL, Java, and Python.
 * L2: Semantic intent for sharing proprietary logic.
 * L3: LLM reasoning for hidden code blocks.
 */
@Component
public class SourceCodeDetector implements Detector {

    // ── Java ──────────────────────────────────────────────────────────────
    private static final Pattern JAVA_CLASS = Pattern.compile(
        "\\b(public|private|protected)\\s+(class|interface|enum)\\s+\\w+");
    private static final Pattern JAVA_ANNOTATION = Pattern.compile(
        "@(Autowired|Service|Repository|Controller|RestController|Component|Entity|Bean)");

    // ── SQL ───────────────────────────────────────────────────────────────
    private static final Pattern SQL_SELECT = Pattern.compile(
        "\\bSELECT\\s+.{1,200}\\s+FROM\\s+\\w+", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern SQL_INSERT = Pattern.compile(
        "\\bINSERT\\s+INTO\\s+\\w+", Pattern.CASE_INSENSITIVE);

    // ── Python ────────────────────────────────────────────────────────────
    private static final Pattern PYTHON_DEF = Pattern.compile(
        "^def\\s+\\w+\\s*\\(", Pattern.MULTILINE);

    private static final List<String> CODE_KEYWORDS = Arrays.asList("code", "script", "function", "method", "class", "database", "query");
    private static final List<String> INTENT_KEYWORDS = Arrays.asList("here is", "fix", "debug", "review", "check", "run");

    public SourceCodeDetector() {
    }

    @Override
    public String getName() {
        return "SourceCodeDetector";
    }

    @Override
    public List<DetectionResult> detect(DetectionContext context) {
        return detect(context.getPrompt(), context.getDecision());
    }

    public List<DetectionResult> detect(String prompt, OllamaService.LlmDecision decision) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // ── LAYER 1: REGEX ───────────────────────────────────────────
        runRegexLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 2: SEMANTIC ────────────────────────────────────────
        runSemanticLayer(prompt, results);
        if (!results.isEmpty()) return results;

        // ── LAYER 3: LLM (Reusing shared decision) ───────────────────
        runLlamaLayer(prompt, results, decision);

        return results;
    }

    private void runRegexLayer(String prompt, List<DetectionResult> results) {
        if (JAVA_CLASS.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 70, "L1_CODE: Java Class", snippet(prompt, JAVA_CLASS)));
        }
        if (JAVA_ANNOTATION.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 60, "L1_CODE: Java Annotation", snippet(prompt, JAVA_ANNOTATION)));
        }
        if (SQL_SELECT.matcher(prompt).find() || SQL_INSERT.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 55, "L1_CODE: SQL Query", "SQL detected"));
        }
        if (PYTHON_DEF.matcher(prompt).find()) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 50, "L1_CODE: Python Function", snippet(prompt, PYTHON_DEF)));
        }
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        boolean hasCodeRef = CODE_KEYWORDS.stream().anyMatch(w -> lower.contains(w));
        boolean hasIntent = INTENT_KEYWORDS.stream().anyMatch(w -> lower.contains(w));
        if (hasCodeRef && hasIntent) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, 65, "L2_CODE_INTENT", "Potential code sharing intent detected."));
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 70 && (decision.reason.toUpperCase().contains("CODE") || decision.reason.toUpperCase().contains("SOURCE"))) {
            results.add(new DetectionResult(RiskType.SOURCE_CODE, decision.score, "L3_CODE_LLM: " + decision.reason, prompt));
        }
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
