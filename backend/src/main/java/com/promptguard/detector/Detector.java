package com.promptguard.detector;

import com.promptguard.model.DetectionResult;
import java.util.List;

/**
 * Detector — Unified interface for all security tools.
 */
public interface Detector {
    /**
     * @return Unique name of the security tool
     */
    String getName();

    /**
     * Executes the detection logic.
     */
    List<DetectionResult> detect(DetectionContext context);
}
