package com.revature.user.controllers;


import com.revature.user.dtos.ResetPasswordRequest;
import com.revature.user.dtos.SecurityQuestionDTO;
import com.revature.user.dtos.UserQuestionAnswer;
import com.revature.user.dtos.VerifySecurityAnswersRequest;
import com.revature.user.models.SecurityQuestionMaster;
import com.revature.user.repository.SecurityQuestionRepository;
import com.revature.user.repository.UserRepository;
import com.revature.user.security.CustomUserDetails;
import com.revature.user.services.ForgotPasswordService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/forgot")

@RequiredArgsConstructor
public class ForgotPasswordController {

    private final ForgotPasswordService service;
    private final SecurityQuestionRepository masterRepo;
 private final UserRepository userRepo;

    @GetMapping("/user-exists/{username}")
    public boolean userExists(@PathVariable String username) {

        return userRepo.findByUsername(username).isPresent();
    }

    @GetMapping("/questions/{username}")
    public List<UserQuestionAnswer> getQuestions(
            @PathVariable String username) {

        return service.getUserQuestionsWithMask(username);
    }

    // ✅ Step 2 — Verify Answers
    @PostMapping("/verify")
    public String verify(
            @RequestBody VerifySecurityAnswersRequest request) {

        boolean result =
                service.verifyAnswers(request);

        return result ?
                "VERIFIED" :
                "INVALID_ANSWERS";
    }

    // ✅ Step 3 — Reset Password
    @PostMapping("/reset")
    public String reset(
            @RequestBody ResetPasswordRequest request) {

        return service.resetPassword(request);
    }

}

