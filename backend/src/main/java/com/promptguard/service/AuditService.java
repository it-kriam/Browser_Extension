package com.promptguard.service;

import com.promptguard.model.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private final JdbcTemplate db;
    private final TokenService tokenService;

    public AuditService(JdbcTemplate db, TokenService tokenService) {
        this.db = db;
        this.tokenService = tokenService;
    }

    @Async
    public void log(PromptRequest request,
            RiskScore riskScore,
            PolicyDecision decision,
            String finalPrompt,
            long processingTimeMs) {

        String userId = (request.getUserId() != null && !request.getUserId().isBlank())
                ? request.getUserId().trim()
                : "anonymous-user";

        String actionLabel = (decision != null && decision.getAction() != null) ? decision.getAction().name() : "ALLOW";
        int scoreLabel     = (riskScore != null) ? riskScore.getTotalScore() : 0;
        System.out.println("[AuditService] 📥 RECEIVED log() — user=" + userId
                + ", action=" + actionLabel + ", score=" + scoreLabel
                + ", tool=" + (request.getTool() != null ? request.getTool() : "Unknown")
                + ", testing=" + request.isTesting());

        try {
            java.util.UUID logId = java.util.UUID.randomUUID();
            String riskType = (riskScore != null && riskScore.getRiskType() != null) ? riskScore.getRiskType().name() : "NONE";
            String riskLevel = (riskScore != null && riskScore.getRiskLevel() != null) ? riskScore.getRiskLevel().name() : "NONE";
            int score = (riskScore != null) ? riskScore.getTotalScore() : 0;
            String action = (decision != null && decision.getAction() != null) ? decision.getAction().name() : "ALLOW";
            String reason = (decision != null) ? decision.getReason() : "";

            String originalPrompt = request.getPrompt();
            String tool = (request.getTool() != null) ? request.getTool() : "Unknown";

            int inputOri = tokenService.countTokens(originalPrompt);
            int outputOri = tokenService.getEstimateResponseTokens(originalPrompt);
            double costOri = tokenService.calculateCost(tool, inputOri, outputOri);

            int tkUsed = 0, tkSaved = 0;
            double cUsed = 0.0, cSaved = 0.0;

            if ("BLOCK".equals(action)) {
                tkSaved = inputOri + outputOri;
                cSaved = costOri;
            } else if ("REDACT".equals(action)) {
                int inputRed = tokenService.countTokens(finalPrompt);
                int outputRed = tokenService.getEstimateResponseTokens(finalPrompt);
                tkUsed = inputRed + outputRed;
                cUsed = tokenService.calculateCost(tool, inputRed, outputRed);
                tkSaved = Math.max(0, (inputOri + outputOri) - tkUsed);
                cSaved = Math.max(0, costOri - cUsed);
            } else {
                tkUsed = inputOri + outputOri;
                cUsed = costOri;
            }

            // 🧪 Only skip database storage for the Dashboard UI Playground. 
            // 📑 Popup tests and production traffic are always stored.
            if (request.isTesting() && "DashboardTest".equalsIgnoreCase(tool)) {
                System.out.println("[AuditService] 🧪 TEST ONLY 🧪 No db storage. Result: User=" + userId + ", Action=" + action + ", Score=" + score + " (" + riskType + ")");
                return;
            }

            db.update(
                "INSERT INTO audit_logs " +
                "(id, user_id, tool, browser_name, original_prompt, redacted_prompt, " +
                " highest_risk_type, risk_score, risk_level, action, action_reason, " +
                " processing_time_ms, tokens_used, tokens_saved, cost_used, cost_saved) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                logId, userId, tool,
                (request.getBrowserName() != null ? request.getBrowserName() : "Unknown"),
                originalPrompt, finalPrompt,
                riskType, score, riskLevel, action, reason,
                processingTimeMs, tkUsed, tkSaved, cUsed, cSaved
            );

            System.out.println("[AuditService] ✅ SUCCESS ✅ Log stored: " + logId + " for user: " + userId);
        } catch (Exception e) {
            System.err.println("[AuditService] ❌ CRITICAL FAILURE ❌ user=" + userId
                + ", action=" + actionLabel + ", error=" + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("[AuditService] ❌ Caused by: " + e.getCause().getMessage());
            }
            e.printStackTrace();
        }
    }
}
