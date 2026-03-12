package com.revature.user.services;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "notification-service")
public interface NotificationClient {

    @GetMapping("/api/otp/generate")
    String generateOtp(@RequestParam("email") String email);

    @PostMapping("/api/otp/verify")
    boolean verifyOtp(@RequestParam("email") String email, @RequestParam("otp") String otp);
}
