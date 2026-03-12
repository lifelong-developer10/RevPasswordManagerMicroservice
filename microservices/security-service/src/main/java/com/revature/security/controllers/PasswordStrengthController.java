package com.revature.security.controllers;

import com.revature.security.dtos.PasswordStrengthResponse;
import com.revature.security.services.PasswordStrengthService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
public class PasswordStrengthController {

    private final PasswordStrengthService strengthService;

    @GetMapping("/strength")
    public PasswordStrengthResponse strength(
            @RequestParam String password) {

        return strengthService.analyze(password);
    }
}
