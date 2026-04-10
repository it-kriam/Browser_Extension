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
 * CryptocurrencyDetector — 3-Layer Intelligent Crypto Shield.
 * L1: Regex detection for Wallet Addresses and Private Keys.
 * L2: Semantic intent for financial transactions / seed phrase sharing.
 * L3: LLM reasoning for obfuscated crypto fraud or leaks.
 */
@Component
public class CryptocurrencyDetector implements Detector {

    // Crypto wallet addresses (Public) -> high risk SECRET, results in BLOCK
    private static final List<Pattern> WALLET_ADDRESS_PATTERNS = List.of(
            Pattern.compile("\\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\\b"),
            Pattern.compile("\\b0x[a-fA-F0-9]{40}\\b"),
            Pattern.compile("\\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\\b")
    );

    // Crypto Private Keys -> highly sensitive SECRET, results in BLOCK
    private static final List<Pattern> PRIVATE_KEY_PATTERNS = List.of(
            Pattern.compile("\\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\\b")
    );

    private static final Set<String> CRYPTO_SECRET_KEYWORDS = Set.of(
        "private key", "seed phrase", "recovery phrase", 
        "mnemonic phrase", "wallet import format", "wif key"
    );

    private static final Set<String> CRYPTO_WALLET_KEYWORDS = Set.of(
        "crypto wallet", "wallet address", "bitcoin address", 
        "ethereum address", "litecoin address"
    );

    public CryptocurrencyDetector() {
    }

    @Override
    public String getName() {
        return "CryptocurrencyDetector";
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
        for (Pattern pattern : PRIVATE_KEY_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 95, "L1_CRYPTO: Private Key", m.group()));
                match = true;
            }
        }
        for (Pattern pattern : WALLET_ADDRESS_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            if (m.find()) {
                String wallet = m.group();
                results.add(new DetectionResult(RiskType.SECRET, 85, "L1_CRYPTO: Wallet (" + classifyWallet(wallet) + ")", wallet));
                match = true;
            }
        }
        return match;
    }

    private void runSemanticLayer(String prompt, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : CRYPTO_SECRET_KEYWORDS) {
            if (lower.contains(kw)) {
                results.add(new DetectionResult(RiskType.SECRET, 90, "L2_CRYPTO_SECRET: " + kw, kw));
                return;
            }
        }
        for (String kw : CRYPTO_WALLET_KEYWORDS) {
            if (lower.contains(kw)) {
                results.add(new DetectionResult(RiskType.SECRET, 75, "L2_CRYPTO_WALLET: " + kw, kw));
                return;
            }
        }
    }

    private void runLlamaLayer(String prompt, List<DetectionResult> results, OllamaService.LlmDecision decision) {
        if (decision.score >= 80 && (decision.reason.toUpperCase().contains("CRYPTO") || decision.reason.toUpperCase().contains("WALLET") || decision.reason.toUpperCase().contains("BITCOIN"))) {
            results.add(new DetectionResult(RiskType.SECRET, decision.score, "L3_CRYPTO_LLM: " + decision.reason, prompt));
        }
    }

    private String classifyWallet(String match) {
        if (match.startsWith("0x")) return "Ethereum";
        if (match.startsWith("1") || match.startsWith("3") || match.startsWith("bc1")) return "Bitcoin";
        if (match.startsWith("L") || match.startsWith("M")) return "Litecoin";
        return "Unknown Crypto";
    }
}
