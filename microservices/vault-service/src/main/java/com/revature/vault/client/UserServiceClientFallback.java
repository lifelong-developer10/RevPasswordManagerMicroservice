package com.revature.vault.client;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
public class UserServiceClientFallback implements UserServiceClient {

    @Override
    public ResponseEntity<String> getUserStatus(Long id) {
        return ResponseEntity.ok("User service unavailable. Circuit Breaker fallback invoked.");
    }
}
