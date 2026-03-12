package com.revature.user.dtos;

import lombok.Data;

import java.util.Map;

@Data
public class VerifySecurityAnswersRequest {

    private String username;
    // questionId -> answer
    private Map<Long, String> answers;
}
