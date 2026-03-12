package com.revature.security.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PasswordStrengthResponse {

    private String strength;
    private int score;
}
