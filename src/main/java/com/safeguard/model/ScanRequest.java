package com.safeguard.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ScanRequest(
        @NotBlank(message = "Text is required")
        @Size(max = 10000, message = "Text must not exceed 10000 characters")
        String text,

        @Size(max = 50, message = "Source must not exceed 50 characters")
        String source
) {
}
