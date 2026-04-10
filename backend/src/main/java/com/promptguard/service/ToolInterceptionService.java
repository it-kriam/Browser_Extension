package com.promptguard.service;

import com.promptguard.detector.Detector;
import com.promptguard.detector.DetectionContext;
import com.promptguard.model.DetectionResult;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * ToolInterceptionService — The Hook for AI Tool Security.
 * This service allows us to intercept every detector call for auditing, 
 * performance tracking, or custom pre-execution logic.
 */
@Service
public class ToolInterceptionService {

    /**
     * Intercepts a tool execution and applies global security/audit logic.
     */
    public List<DetectionResult> interceptAndExecute(Detector tool, DetectionContext context) {
        long startTime = System.currentTimeMillis();

        // ── PRE-INTERCEPTION: Can add global bypass rules or pre-processing here ─────
        // System.out.println("[Tool Interceptor] START: " + tool.getName() + " on prompt...");

        // Execute the tool logic
        List<DetectionResult> results = tool.detect(context);

        // ── POST-INTERCEPTION: Performance tracking and result filtering ──────────────
        long duration = System.currentTimeMillis() - startTime;
        
        if (!results.isEmpty()) {
            System.out.println("[Tool Interceptor] 🚨 DETECTED: " + tool.getName() 
                + " found " + results.size() + " risks in " + duration + "ms.");
        } else {
            // System.out.println("[Tool Interceptor] Safe: " + tool.getName() + " (" + duration + "ms)");
        }

        return results;
    }
}
