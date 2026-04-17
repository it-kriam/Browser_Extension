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

/**
 * PromptValidationService — The Orchestrator.
 * Optimized for High Performance & Low Latency.
 * LLM stage removed. Only fast Semantic & Regex patterns are used.
 */
@Service
public class PromptValidationService {

    private final JailbreakDetector jailbreakDetector;
    private final SecretDetector secretDetector;
    private final PiiDetector piiDetector;
    private final PhiDetector phiDetector;
    private final KeywordDetector keywordDetector;
    private final UserKeywordDetector userKeywordDetector;
    private final UserRepository userRepository;
    private final ToolInterceptionService interceptionService;
    private final InputNormalizer normalizer;
    private final List<Detector> coreDetectors;
    // Time-bounded cache: entries expire after 5 minutes to prevent stale scores after recalibration.
    private static final long CACHE_TTL_MS = 5 * 60 * 1000L;
    private final java.util.concurrent.ConcurrentHashMap<String, long[]> cacheTimes   = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, List<DetectionResult>> validationCache = new java.util.concurrent.ConcurrentHashMap<>();

    public PromptValidationService(JailbreakDetector jailbreakDetector,
            SecretDetector secretDetector,
            PiiDetector piiDetector,
            PhiDetector phiDetector,
            KeywordDetector keywordDetector,
            UserKeywordDetector userKeywordDetector,
            UserRepository userRepository,
            ToolInterceptionService interceptionService,
            InputNormalizer normalizer) {
        this.jailbreakDetector = jailbreakDetector;
        this.secretDetector = secretDetector;
        this.piiDetector = piiDetector;
        this.phiDetector = phiDetector;
        this.keywordDetector = keywordDetector;
        this.userKeywordDetector = userKeywordDetector;
        this.userRepository = userRepository;
        this.interceptionService = interceptionService;
        this.normalizer = normalizer;

        // Initialize core high-speed detectors
        this.coreDetectors = List.of(secretDetector, piiDetector, phiDetector, keywordDetector);
    }

    public List<DetectionResult> validate(String prompt, String userId, String subUser) {
        if (prompt == null || prompt.isBlank())
            return Collections.emptyList();

        // Check Cache Phase (with TTL expiry)
        String cacheKey = userId + "::" + subUser + "::" + prompt;
        long[] ts = cacheTimes.get(cacheKey);
        if (ts != null && (System.currentTimeMillis() - ts[0]) < CACHE_TTL_MS && validationCache.containsKey(cacheKey)) {
            return validationCache.get(cacheKey);
        }
        // Evict stale entry if expired
        if (ts != null) {
            validationCache.remove(cacheKey);
            cacheTimes.remove(cacheKey);
        }

        // PHASE 0: Advanced Normalization
        String normalized = normalizer.normalize(prompt);

        // High-Speed Detection Context
        DetectionContext context = new DetectionContext(prompt, normalized, userId, subUser);

        // PHASE 1: Injection Firewall (Sequential)
        List<DetectionResult> results = new ArrayList<>(
                interceptionService.interceptAndExecute(jailbreakDetector, context));

        // PHASE 2: Core Data Protection (Parallel Execution)
        List<CompletableFuture<List<DetectionResult>>> futures = coreDetectors.stream()
                .map(tool -> CompletableFuture
                        .supplyAsync(() -> interceptionService.interceptAndExecute(tool, context)))
                .collect(Collectors.toList());

        List<DetectionResult> parallelResults = futures.stream()
                .map(CompletableFuture::join)
                .flatMap(List::stream)
                .collect(Collectors.toList());
        results.addAll(parallelResults);

        // PHASE 3: Organizational Policy
        String orgKey = resolveOrgName(userId);
        DetectionContext orgContext = new DetectionContext(prompt, normalized, orgKey, subUser);
        results.addAll(interceptionService.interceptAndExecute(userKeywordDetector, orgContext));

        validationCache.put(cacheKey, results);
        cacheTimes.put(cacheKey, new long[]{ System.currentTimeMillis() });
        return results;
    }

    private final java.util.concurrent.ConcurrentHashMap<String, String> orgCache = new java.util.concurrent.ConcurrentHashMap<>();

    private String resolveOrgName(String userId) {
        if (userId == null || userId.isBlank())
            return userId;

        if (orgCache.containsKey(userId)) {
            return orgCache.get(userId);
        }

        try {
            Optional<User> userOpt = userRepository.findByUserId(userId);
            if (userOpt.isPresent() && userOpt.get().getOrgId() != null) {
                String orgName = String.valueOf(userOpt.get().getOrgId());
                orgCache.put(userId, orgName);
                return orgName;
            }
        } catch (Exception ignored) {
        }
        
        // Cache misses / defaults too to avoid repeating failing DB queries
        orgCache.put(userId, userId);
        return userId;
    }
}
