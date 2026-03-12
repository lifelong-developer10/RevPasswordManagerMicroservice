package com.revature.vault.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class AllPasswordEntry {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        private String accountName;
        private String website;
        private String username;
        private String passwordEncrypted;
        private String category;
        private String notes;
        private boolean favorite;

        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        private String ownerUsername;
    }


