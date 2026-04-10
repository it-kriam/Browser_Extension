package com.promptguard.service;

import com.promptguard.detector.*;
import com.promptguard.model.DetectionResult;
import com.promptguard.model.User;
import com.promptguard.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * PromptValidationService — The Orchestrator.
 * Now optimized with Parallel Execution to minimize latency.
 */
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
    private final OllamaService ollamaService;
    private final UserRepository userRepository;
    private final ToolInterceptionService interceptionService;
    private final List<Detector> parallelTools;

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
            OllamaService ollamaService,
            UserRepository userRepository,
            ToolInterceptionService interceptionService) {
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
        this.ollamaService = ollamaService;
        this.userRepository = userRepository;
        this.interceptionService = interceptionService;

        // Initialize the parallel tool list
        this.parallelTools = List.of(
            secretDetector, piiDetector, phiDetector, sourceCodeDetector,
            keywordDetector, cryptocurrencyDetector, ipAddressDetector,
            jwtDetector, databaseConnectionDetector, cloudProviderDetector
        );
    }

    public List<DetectionResult> validate(String prompt, String userId, String subUser) {
        if (prompt == null || prompt.isBlank()) return Collections.emptyList();

        // ── PHASE 0: Global LLM Decision (Single-Pass) ────────────────────
        OllamaService.LlmDecision globalDecision = ollamaService.predictRisk(prompt);
        DetectionContext context = new DetectionContext(prompt, userId, subUser, globalDecision);

        // ── PHASE 1: Jailbreak Firewall (Sequential Interception) ─────────
        List<DetectionResult> results = new ArrayList<>(
            interceptionService.interceptAndExecute(jailbreakDetector, context));

        // ── PHASE 2: Global Detectors (Parallel Interception) ─────────────
        List<CompletableFuture<List<DetectionResult>>> futures = parallelTools.stream()
            .map(tool -> CompletableFuture.supplyAsync(() -> 
                interceptionService.interceptAndExecute(tool, context)))
            .collect(Collectors.toList());

        // Wait for all Phase 2 detectors
        List<DetectionResult> parallelResults = futures.stream()
                .map(CompletableFuture::join)
                .flatMap(List::stream)
                .collect(Collectors.toList());
        results.addAll(parallelResults);

        // ── PHASE 3: Org-specific policies ───────────────────────────────────
        String orgKey = resolveOrgName(userId);
        DetectionContext orgContext = new DetectionContext(prompt, orgKey, subUser, globalDecision);
        results.addAll(interceptionService.interceptAndExecute(userKeywordDetector, orgContext));

        return results;
    }

    private String resolveOrgName(String userId) {
        if (userId == null || userId.isBlank()) return userId;
        try {
            Optional<User> userOpt = userRepository.findByUserId(userId);
            if (userOpt.isPresent() && userOpt.get().getOrgId() != null) {
                return String.valueOf(userOpt.get().getOrgId());
            }
        } catch (Exception ignored) {}
        return userId;
    }
}
