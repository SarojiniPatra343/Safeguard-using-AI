
package com.safeguard.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class RuleEngineService {

    private static final Pattern EMAIL = Pattern.compile(
            "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern PHONE = Pattern.compile(
            "(?<!\\d)(?:\\+?\\d[\\d\\s().-]{7,}\\d)(?!\\d)"
    );

    private static final Pattern INJECTION = Pattern.compile(
            "(?i)ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions"
            + "|reveal\\s+(the\\s+)?(system\\s+)?prompt"
            + "|bypass\\s+(all\\s+)?security"
            + "|disregard\\s+(your\\s+)?instructions"
    );

    // Detect requests for passwords, OTPs, PINs and financial credentials.
    private static final Pattern CREDENTIAL_REQUEST = Pattern.compile(
            "(?i)\\b(password|passcode|otp|one[- ]time password|"
            + "banking pin|credit card number|cvv|security code)\\b"
            + ".{0,100}\\b(send|share|reply|provide|submit|disclose|"
            + "enter|type|give|tell)\\b"
            + "|\\b(send|share|reply with|provide|submit|disclose|"
            + "enter|type|give|tell)\\b"
            + ".{0,100}\\b(password|passcode|otp|one[- ]time password|"
            + "banking pin|credit card number|cvv|security code)\\b"
            + "|\\b(enter|type|provide|share)\\s+your\\s+"
            + "(password|otp|pin|passcode|banking details)\\b"
    );

    // Detect urgency and pressure tactics.
    private static final Pattern URGENCY = Pattern.compile(
            "(?i)\\b(urgent|immediately|act now|right now|"
            + "within\\s+\\d+\\s+minutes?|"
            + "expires? in\\s+\\d+\\s+minutes?|"
            + "only\\s+\\d+\\s+minutes? remaining|"
            + "limited time|final warning|last chance)\\b"
    );

    // Detect threats to accounts or access.
    private static final Pattern ACCOUNT_THREAT = Pattern.compile(
            "(?i)\\b(account|bank account|profile|access)\\b"
            + ".{0,120}\\b(suspend\\w*|block\\w*|restrict\\w*|"
            + "terminat\\w*|clos\\w*|deactivat\\w*)\\b"
            + "|\\b(suspend\\w*|block\\w*|restrict\\w*|"
            + "terminat\\w*|deactivat\\w*)\\b"
            + ".{0,120}\\b(account|bank account|profile|access)\\b"
    );

    // Flag URLs containing common action-related terms.
    // A match is a warning signal, not proof that a URL is malicious.
    private static final Pattern SUSPICIOUS_URL = Pattern.compile(
            "(?i)https?://[^\\s<>\\\"']*"
            + "(login|verify|verification|secure|account|"
            + "reward|claim|update|confirm|password)[^\\s<>\\\"']*"
    );

    // Detect suspicious prize or reward lures.
    private static final Pattern REWARD_SCAM = Pattern.compile(
            "(?i)\\b(won|winner|selected|claim|reward|prize|"
            + "free gift|cash prize)\\b"
            + ".{0,120}(₹\\s?[\\d,]+|\\$\\s?[\\d,]+|"
            + "\\b\\d[\\d,]*\\s*(rupees|dollars)\\b|"
            + "\\b(reward|prize|gift|money|cash)\\b)"
            + "|\\b(reward|prize|gift|cash prize)\\b"
            + ".{0,100}\\b(claim|selected|won|winner|expires?)\\b"
    );

    // Detect explicit impersonation language.
    private static final Pattern IMPERSONATION = Pattern.compile(
            "(?i)\\b(pretend\\s+to\\s+be|impersonat\\w*|"
            + "posing\\s+as)\\b"
            + ".{0,60}\\b(ceo|admin|manager|bank|support|"
            + "security team|government|official)\\b"
    );

    public RuleFindings inspect(String text) {

        List<String> categories = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();

        if (text == null || text.isBlank()) {
            return new RuleFindings(
                    0,
                    List.of("EMPTY_INPUT"),
                    List.of("No text was provided for inspection."),
                    List.of("Enter text before running a security scan.")
            );
        }

        int score = 0;

        // 1. Prompt injection
        if (INJECTION.matcher(text).find()) {
            categories.add("PROMPT_INJECTION");
            evidence.add(
                    "Instruction override or prompt-disclosure language was detected."
            );
            recommendations.add(
                    "Treat the content as untrusted input and never let it override system instructions."
            );
            score += 85;
        }

        // 2. Credential theft
        if (CREDENTIAL_REQUEST.matcher(text).find()) {
            categories.add("CREDENTIAL_THEFT");
            evidence.add(
                    "The message appears to request passwords, OTPs, PINs, or sensitive financial credentials."
            );
            recommendations.add(
                    "Never disclose passwords, OTPs, PINs, or card security details in response to unsolicited messages."
            );
            score += 55;
        }

        // 3. Urgency
        if (URGENCY.matcher(text).find()) {
            categories.add("URGENCY");
            evidence.add(
                    "Urgent wording or a short deadline may pressure the recipient into acting without verification."
            );
            recommendations.add(
                    "Pause and independently verify the request before taking action."
            );
            score += 15;
        }

        // 4. Account threats
        if (ACCOUNT_THREAT.matcher(text).find()) {
            categories.add("ACCOUNT_THREAT");
            evidence.add(
                    "The message threatens account suspension, blocking, deactivation, or restriction."
            );
            recommendations.add(
                    "Check account status using the official application or website instead of a message link."
            );
            score += 25;
        }

        // 5. Suspicious URL patterns
        if (SUSPICIOUS_URL.matcher(text).find()) {
            categories.add("SUSPICIOUS_URL");
            evidence.add(
                    "A URL contains login, verification, account, reward, or similar action-related terms."
            );
            recommendations.add(
                    "Inspect the hostname carefully and navigate to the official website directly."
            );
            score += 20;
        }

        // 6. Reward or prize lures
        if (REWARD_SCAM.matcher(text).find()) {
            categories.add("POTENTIAL_REWARD_SCAM");
            evidence.add(
                    "The text contains reward or prize language that may be used to lure recipients."
            );
            recommendations.add(
                    "Verify unexpected rewards through official channels; never pay suspicious fees or disclose credentials to claim a prize."
            );
            score += 25;
        }

        // 7. Impersonation
        if (IMPERSONATION.matcher(text).find()) {
            categories.add("IMPERSONATION");
            evidence.add(
                    "The message contains language suggesting impersonation of an authority or trusted organization."
            );
            recommendations.add(
                    "Confirm the sender's identity through an independently trusted channel."
            );
            score += 35;
        }

        // 8. Potential personal data
        if (EMAIL.matcher(text).find() || PHONE.matcher(text).find()) {
            categories.add("POTENTIAL_PERSONAL_DATA");
            evidence.add(
                    "An email-address or phone-number pattern was detected."
            );
            recommendations.add(
                    "Avoid sharing real personal information unnecessarily; contact details alone do not prove malicious intent."
            );
            score += 5;
        }

        // Clamp score to 0–100.
        score = Math.min(100, score);

        if (categories.isEmpty()) {
            categories.add("NO_RULE_MATCH");
            evidence.add(
                    "No configured detection rules matched. This does not guarantee that the content is safe."
            );
            recommendations.add(
                    "Continue to follow normal verification and data-handling procedures."
            );
        }

        return new RuleFindings(
                score,
                List.copyOf(categories),
                List.copyOf(evidence),
                List.copyOf(recommendations)
        );
    }

    public record RuleFindings(
            int riskScore,
            List<String> categories,
            List<String> evidence,
            List<String> recommendations
    ) {
    }
}
