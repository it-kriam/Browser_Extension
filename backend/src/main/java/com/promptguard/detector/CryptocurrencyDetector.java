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
public class CryptocurrencyDetector {

    // Crypto wallet addresses (Public) -> high risk SECRET, results in BLOCK
    private static final List<Pattern> WALLET_ADDRESS_PATTERNS = List.of(
            // Bitcoin (P2PKH, P2SH, Bech32)
            Pattern.compile("\\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\\b"),
            // Ethereum
            Pattern.compile("\\b0x[a-fA-F0-9]{40}\\b"),
            // Litecoin
            Pattern.compile("\\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\\b")
    );

    // Crypto Private Keys -> highly sensitive SECRET, results in BLOCK
    private static final List<Pattern> PRIVATE_KEY_PATTERNS = List.of(
            // Wallet Import Format (WIF) used for Bitcoin private keys (starts with 5, K, or L)
            Pattern.compile("\\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\\b")
    );

    // Secret-level crypto keywords
    private static final Set<String> CRYPTO_SECRET_KEYWORDS = Set.of(
        "private key", "seed phrase", "recovery phrase", 
        "mnemonic phrase", "wallet import format", "wif key"
    );

    // Wallet/address level crypto keywords
    private static final Set<String> CRYPTO_WALLET_KEYWORDS = Set.of(
        "crypto wallet", "wallet address", "bitcoin address", 
        "ethereum address", "litecoin address"
    );

    public List<DetectionResult> detect(String prompt) {
        List<DetectionResult> results = new ArrayList<>();
        if (prompt == null || prompt.isBlank()) return results;

        // 1. Detect Private Keys (High Risk, SECRET, Action -> BLOCK)
        for (Pattern pattern : PRIVATE_KEY_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            while (m.find()) {
                results.add(new DetectionResult(
                        RiskType.SECRET,
                        95,
                        "Cryptocurrency Private Key detected: HIGH RISK",
                        m.group()
                ));
            }
        }

        // 2. Detect Wallet Addresses (High Risk, SECRET, Action -> BLOCK)
        for (Pattern pattern : WALLET_ADDRESS_PATTERNS) {
            Matcher m = pattern.matcher(prompt);
            while (m.find()) {
                String match = m.group();
                String cryptoType = classifyWallet(match);
                results.add(new DetectionResult(
                        RiskType.SECRET,
                        85,
                        "Cryptocurrency Wallet Address detected (" + cryptoType + ")",
                        match
                ));
            }
        }

        // Keyword checks
        checkKeywords(prompt, CRYPTO_SECRET_KEYWORDS, RiskType.SECRET, "Crypto Secret Keyword", 85, results);
        checkKeywords(prompt, CRYPTO_WALLET_KEYWORDS, RiskType.SECRET, "Crypto Wallet Keyword", 65, results);

        return results;
    }

    private void checkKeywords(String prompt, Set<String> keywords, RiskType riskType, String label,
                                int score, List<DetectionResult> results) {
        String lower = prompt.toLowerCase();
        for (String kw : keywords) {
            if (lower.contains(kw.toLowerCase())) {
                results.add(new DetectionResult(
                    riskType,
                    score,
                    riskType + " detected: " + label + " — \"" + kw + "\"",
                    kw
                ));
                return; // one hit per category is enough
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
