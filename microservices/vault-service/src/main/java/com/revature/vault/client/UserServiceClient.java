package com.revature.vault.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-service", path = "/api/users", fallback = UserServiceClientFallback.class)
public interface UserServiceClient {

    @GetMapping("/{id}/status")
    ResponseEntity<String> getUserStatus(@PathVariable("id") Long id);
}
