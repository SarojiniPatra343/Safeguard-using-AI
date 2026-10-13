package com.safeguard.model;

import java.util.List;

public record ScanResult(
        int riskScore,
        String riskLevel,
        List<String> categories,
        List<String> evidence,
        List<String> recommendations,
        String decision,
        String analysisMode,
        long processingTimeMs
) {
}
