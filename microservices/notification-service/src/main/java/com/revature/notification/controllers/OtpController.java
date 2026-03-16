package com.revature.notification.controllers;

import com.revature.notification.dtos.OtpRequest;
import com.revature.notification.dtos.OtpVerifyRequest;
import com.revature.notification.services.OtpService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/otp")
@RequiredArgsConstructor
public class OtpController {

    private final OtpService otpService;

    @PostMapping("/generate")
    public ResponseEntity<String> generate(@RequestBody OtpRequest request) {

        String msg = otpService.generateAndSendOtp(request);

        return ResponseEntity.ok(msg);
    }
    @PostMapping("/verify")
    public ResponseEntity<String> verify(@RequestBody OtpVerifyRequest request) {

        boolean result =
                otpService.verifyOtp(
                        request.getUsername(),
                        request.getCode());

        return ResponseEntity.ok(
                result ? "OTP Verified" : "Invalid OTP");
    }


}
