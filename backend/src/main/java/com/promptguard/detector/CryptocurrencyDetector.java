package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import com.promptguard.model.RiskType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CryptocurrencyDetector — High-Performance Crypto Shield.
 * L1: Regex detection for Wallet Addresses and Private Keys.
 * L2: Semantic intent for crypto credential and financial transaction sharing.
 * Short-circuit: L1 hit → L2 skipped.
 */
@Component
public class CryptocurrencyDetector implements Detector {

    // ── L1: Crypto Private Key Patterns ───────────────────────────────────
    private static final List<Pattern> PRIVATE_KEY_PATTERNS = List.of(
        Pattern.compile("\\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\\b")
    );

    // ── L1: Crypto Wallet Address Patterns ────────────────────────────────
    private static final List<Pattern> WALLET_ADDRESS_PATTERNS = List.of(
        Pattern.compile("\\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\\b"),
        Pattern.compile("\\b0x[a-fA-F0-9]{40}\\b"),
        Pattern.compile("\\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\\b")
    );

    // ── L2: High-Risk Secret Keywords (score=90) ──────────────────────────
    private static final List<String> CRYPTO_SECRET_KEYWORDS = List.of(
        "private key", "seed phrase", "recovery phrase", "mnemonic phrase",
        "wallet import format", "wif key", "secret key", "keystore file",
        "12 word phrase", "24 word phrase", "passphrase", "cold wallet key",
        "hot wallet key", "hardware wallet backup", "paper wallet"
    );

    // ── L2: Medium-Risk Wallet Keywords (score=75) ────────────────────────
    private static final List<String> CRYPTO_WALLET_KEYWORDS = List.of(
        "crypto wallet", "wallet address", "bitcoin address", "ethereum address",
        "litecoin address", "metamask address", "trust wallet", "phantom wallet",
        "coinbase wallet", "ledger wallet", "send crypto to", "receive crypto at",
        "deposit address", "withdrawal address", "my btc address", "my eth address"
    );

    // ── L2: Low-Risk Transaction Intent Keywords (score=55) ───────────────
    private static final List<String> CRYPTO_TRANSACTION_KEYWORDS = List.of(
        "transfer crypto", "send bitcoin", "send ethereum", "swap tokens",
        "gas fee", "transaction hash", "block explorer", "mining reward",
        "staking reward", "yield farming", "liquidity pool", "defi protocol",
        "smart contract address", "nft contract", "token contract"
    );

    private static final Pattern INQUIRY_PATTERN = Pattern.compile(
        "\\b(safe|ok|okay|can i|should i|is it|allowed|policy|how to|is it safe|tell me about)\\b",
        Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "CryptocurrencyDetector"; }

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
        for (Pattern pattern : PRIVATE_KEY_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            if (m.find()) {
                results.add(new DetectionResult(RiskType.SECRET, 95,
                    "L1_CRYPTO_REGEX: Private Key", m.group()));
                match = true;
            }
        }
        for (Pattern pattern : WALLET_ADDRESS_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            if (m.find()) {
                String wallet = m.group();
                results.add(new DetectionResult(RiskType.SECRET, 85,
                    "L1_CRYPTO_REGEX: Wallet (" + classifyWallet(wallet) + ")", wallet));
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
            results.add(new DetectionResult(RiskType.SECRET, 20, "L2_CRYPTO_INQUIRY",
                "INFO: User is inquiring about crypto safety, not disclosing credentials."));
            return;
        }

        // Tier 1: Secret keywords → score 90 (BLOCK)
        for (String kw : CRYPTO_SECRET_KEYWORDS) {
            if (normalized.contains(kw.replace(" ", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 90,
                    "L2_CRYPTO_SECRET: " + kw, kw));
                return;
            }
        }
        // Tier 2: Wallet keywords → score 75 (REDACT)
        for (String kw : CRYPTO_WALLET_KEYWORDS) {
            if (normalized.contains(kw.replace(" ", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 75,
                    "L2_CRYPTO_WALLET: " + kw, kw));
                return;
            }
        }
        // Tier 3: Transaction keywords → score 55 (ALERT)
        for (String kw : CRYPTO_TRANSACTION_KEYWORDS) {
            if (normalized.contains(kw.replace(" ", "").toLowerCase())) {
                results.add(new DetectionResult(RiskType.SECRET, 55,
                    "L2_CRYPTO_TRANSACTION: " + kw, kw));
                return;
            }
        }
    }

    private String classifyWallet(String match) {
        if (match.startsWith("0x")) return "Ethereum";
        if (match.startsWith("1") || match.startsWith("3") || match.startsWith("bc1")) return "Bitcoin";
        if (match.startsWith("L") || match.startsWith("M")) return "Litecoin";
        return "Unknown Crypto";
    }
}
