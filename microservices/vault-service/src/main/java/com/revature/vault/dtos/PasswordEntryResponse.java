package com.revature.vault.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
@Data
@AllArgsConstructor
@NoArgsConstructor

@Builder
public class PasswordEntryResponse {

        private Long id;
        private String accountName;
        private String website;
        private String username;
        private String password;
        private String category;
        private String notes;
        private boolean favorite;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

    }

