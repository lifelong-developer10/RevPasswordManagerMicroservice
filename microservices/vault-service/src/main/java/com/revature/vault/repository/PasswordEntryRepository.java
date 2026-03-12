package com.revature.vault.repository;

import com.revature.vault.models.AllPasswordEntry;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
public interface PasswordEntryRepository
        extends JpaRepository<AllPasswordEntry, Long> {

    List<AllPasswordEntry> findByOwnerUsername(String ownerUsername);

    List<AllPasswordEntry> findByOwnerUsernameAndCategory(
            String ownerUsername, String category);

    List<AllPasswordEntry> findByOwnerUsernameAndFavoriteTrue(
            String ownerUsername);

    List<AllPasswordEntry> findByOwnerUsernameAndAccountNameContainingIgnoreCase(
            String ownerUsername, String keyword);

    Optional<AllPasswordEntry>
    findTopByOwnerUsernameOrderByCreatedAtDesc(String ownerUsername);
}

