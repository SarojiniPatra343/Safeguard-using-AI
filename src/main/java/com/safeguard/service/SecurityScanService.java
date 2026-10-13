package com.safeguard.service;

import com.safeguard.model.ScanRequest;
import com.safeguard.model.ScanResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class SecurityScanService {
    private final RuleEngineService ruleEngine;
    private final AiAnalysisService aiAnalysis;

    public SecurityScanService(RuleEngineService ruleEngine, AiAnalysisService aiAnalysis) {
        this.ruleEngine = ruleEngine;
        this.aiAnalysis = aiAnalysis;
    }

    public ScanResult scan(ScanRequest request) {
        long started = System.nanoTime();
        RuleEngineService.RuleFindings rules = ruleEngine.inspect(request.text());
        int score = rules.riskScore();
        Set<String> categories = new LinkedHashSet<>(rules.categories());
        List<String> evidence = new ArrayList<>(rules.evidence());
        List<String> recommendations = new ArrayList<>(rules.recommendations());
        String mode = "RULES_ONLY";

        if (aiAnalysis.isEnabled()) {
            try {
                String analysis = aiAnalysis.analyze(request.text());
                if (analysis != null && !analysis.isBlank()) {
                    mode = "RULES_AND_GEMINI";
                    evidence.add("AI contextual assessment: " + limit(analysis.trim(), 1200));
                    String normalized = analysis.toLowerCase(Locale.ROOT);
                    if (containsAny(normalized, "critical", "high risk", "credential theft",
                            "prompt injection", "social engineering", "fraudulent")) {
                        score = Math.max(score, 60);
                        categories.add("AI_FLAGGED_RISK");
                        recommendations.add("Review the AI assessment and independently verify the content before acting.");
                    }
                }
            } catch (Exception ignored) {
                // Fail safely: deterministic rules remain available if the provider is unavailable.
                mode = "RULES_FALLBACK";
                evidence.add("AI assessment was unavailable; the result uses deterministic rules only.");
            }
        }

        score = Math.max(0, Math.min(100, score));
        String level = score >= 80 ? "CRITICAL"
                : score >= 60 ? "HIGH"
                : score >= 40 ? "MEDIUM" : "LOW";
        String decision = score >= 80 ? "BLOCK"
                : score >= 40 ? "REVIEW" : "ALLOW";

        if (score >= 40) {
            recommendations.add("Do not take irreversible action until a human has reviewed this result.");
        }

        return new ScanResult(score, level, List.copyOf(categories), List.copyOf(evidence),
                List.copyOf(new LinkedHashSet<>(recommendations)), decision, mode,
                (System.nanoTime() - started) / 1_000_000);
    }

    private static boolean containsAny(String value, String... terms) {
        for (String term : terms) {
            if (value.contains(term)) return true;
        }
        return false;
    }

    private static String limit(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }
}
