package com.safeguard.controller;

import com.safeguard.model.ScanRequest;
import com.safeguard.model.ScanResult;
import com.safeguard.service.SecurityScanService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class ScanController {
    private final SecurityScanService scanService;

    public ScanController(SecurityScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping("/scan")
    public ScanResult scan(@Valid @RequestBody ScanRequest request) {
        return scanService.scan(request);
    }
}
