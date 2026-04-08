package com.promptguard.service;

import com.promptguard.detector.*;
import com.promptguard.model.DetectionResult;
import com.promptguard.model.User;
import com.promptguard.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class PromptValidationService {

    private final JailbreakDetector jailbreakDetector;
    private final SecretDetector secretDetector;
    private final PiiDetector piiDetector;
    private final PhiDetector phiDetector;
    private final SourceCodeDetector sourceCodeDetector;
    private final KeywordDetector keywordDetector;
    private final UserKeywordDetector userKeywordDetector;
    private final CryptocurrencyDetector cryptocurrencyDetector;
    private final IpAddressDetector ipAddressDetector;
    private final JwtDetector jwtDetector;
    private final DatabaseConnectionDetector databaseConnectionDetector;
    private final CloudProviderDetector cloudProviderDetector;
    private final UserRepository userRepository;

    public PromptValidationService(JailbreakDetector jailbreakDetector,
            SecretDetector secretDetector,
            PiiDetector piiDetector,
            PhiDetector phiDetector,
            SourceCodeDetector sourceCodeDetector,
            KeywordDetector keywordDetector,
            UserKeywordDetector userKeywordDetector,
            CryptocurrencyDetector cryptocurrencyDetector,
            IpAddressDetector ipAddressDetector,
            JwtDetector jwtDetector,
            DatabaseConnectionDetector databaseConnectionDetector,
            CloudProviderDetector cloudProviderDetector,
            UserRepository userRepository) {
        this.jailbreakDetector = jailbreakDetector;
        this.secretDetector = secretDetector;
        this.piiDetector = piiDetector;
        this.phiDetector = phiDetector;
        this.sourceCodeDetector = sourceCodeDetector;
        this.keywordDetector = keywordDetector;
        this.userKeywordDetector = userKeywordDetector;
        this.cryptocurrencyDetector = cryptocurrencyDetector;
        this.ipAddressDetector = ipAddressDetector;
        this.jwtDetector = jwtDetector;
        this.databaseConnectionDetector = databaseConnectionDetector;
        this.cloudProviderDetector = cloudProviderDetector;
        this.userRepository = userRepository;
    }

    public List<DetectionResult> validate(String prompt, String userId, String subUser) {
        List<DetectionResult> all = new ArrayList<>();

        // ── PHASE 0: Global Jailbreak Detector (High Priority) ──────────────
        all.addAll(jailbreakDetector.detect(prompt));

        // ── PHASE 1: Global detectors — same rules for ALL users/orgs ────────
        all.addAll(secretDetector.detect(prompt));
        all.addAll(piiDetector.detect(prompt));
        all.addAll(phiDetector.detect(prompt));
        all.addAll(sourceCodeDetector.detect(prompt));
        all.addAll(keywordDetector.detect(prompt));
        all.addAll(cryptocurrencyDetector.detect(prompt));
        all.addAll(ipAddressDetector.detect(prompt));
        all.addAll(jwtDetector.detect(prompt));
        all.addAll(databaseConnectionDetector.detect(prompt));
        all.addAll(cloudProviderDetector.detect(prompt));

        // ── PHASE 2: Org-specific keyword check ───────────────────────────────
        String orgKey = userId;
        if (userId != null && !userId.isBlank()) {
            try {
                Optional<User> userOpt = userRepository.findByUserId(userId);
                if (userOpt.isPresent() && userOpt.get().getOrgId() != null) {
                    orgKey = String.valueOf(userOpt.get().getOrgId());
                }
            } catch (Exception e) {
            }
        }

        all.addAll(userKeywordDetector.detect(orgKey, subUser, prompt));

        return all;
    }
}
