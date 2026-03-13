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

    @Column(nullable = false, length = 100)
    private String accountName;

    @Column(nullable = false, length = 255)
    private String website;

    @Column(nullable = false, length = 100)
    private String username;

    @Column(nullable = false, length = 512)
    private String passwordEncrypted;

    @Column(nullable = false, length = 50)
    private String category;

    @Column(length = 500)
    private String notes;

    private boolean favorite;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column(nullable = false)
    private String ownerUsername;
    }


