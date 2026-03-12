package com.revature.security.services;

import com.revature.security.dtos.PasswordStrengthResponse;
import org.springframework.stereotype.Service;

@Service
public class PasswordStrengthService {

    public PasswordStrengthResponse analyze(String password) {

        int score = 0;

        if (password.length() >= 8) score++;
        if (password.length() >= 12) score++;

        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*[0-9].*")) score++;
        if (password.matches(".*[!@#$%^&*()].*")) score++;

        String strength;

        if (score <= 2) strength = "Weak";
        else if (score <= 4) strength = "Medium";
        else if (score == 5) strength = "Strong";
        else strength = "Very Strong";

        return new PasswordStrengthResponse(strength, score);
    }
}
