package com.revature.vault.services;

import com.revature.vault.dtos.PasswordEntryRequest;
import com.revature.vault.dtos.PasswordEntryResponse;
import com.revature.vault.models.AllPasswordEntry;
import com.revature.vault.security.EncryptionUtil;
import com.revature.vault.repository.PasswordEntryRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PasswordEntryService {

    private final PasswordEntryRepository repo;
    private final EncryptionUtil encryptionUtil;



    public PasswordEntryResponse addEntry(
            String username,
            PasswordEntryRequest request) throws Exception {



        AllPasswordEntry entry = new AllPasswordEntry();

        entry.setAccountName(request.getAccountName());
        entry.setWebsite(request.getWebsite());
        entry.setUsername(request.getUsername());

        entry.setPasswordEncrypted(
                encryptionUtil.encrypt(request.getPassword()));

        entry.setCategory(request.getCategory());
        entry.setNotes(request.getNotes());
        entry.setFavorite(request.isFavorite());

        entry.setCreatedAt(LocalDateTime.now());
        entry.setUpdatedAt(LocalDateTime.now());

        entry.setOwnerUsername(username);

        repo.save(entry);

        return mapToResponse(entry);
    }

    public PasswordEntryResponse getLastEntry(String username) throws Exception {

        AllPasswordEntry entry =
                repo.findTopByOwnerUsernameOrderByCreatedAtDesc(username)
                        .orElse(null);

        if (entry == null) return null;

        PasswordEntryResponse res = new PasswordEntryResponse();

        res.setId(entry.getId());
        res.setAccountName(entry.getAccountName());
        res.setWebsite(entry.getWebsite());
        res.setUsername(entry.getUsername());

        res.setPassword(
                encryptionUtil.decrypt(entry.getPasswordEncrypted())
        );

        res.setCategory(entry.getCategory());
        res.setNotes(entry.getNotes());
        res.setFavorite(entry.isFavorite());

        return res;
    }

    public List<PasswordEntryResponse> getAllEntries(String username)
            throws Exception {

        return repo.findByOwnerUsername(username)
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public PasswordEntryResponse getEntry(Long id)
            throws Exception {

        AllPasswordEntry entry = repo.findById(id).orElseThrow();

        return mapToResponse(entry);
    }

    public PasswordEntryResponse updateEntry(
            Long id,
            PasswordEntryRequest request) throws Exception {

        AllPasswordEntry entry = repo.findById(id).orElseThrow();

        entry.setAccountName(request.getAccountName());
        entry.setWebsite(request.getWebsite());
        entry.setUsername(request.getUsername());

        entry.setPasswordEncrypted(
                encryptionUtil.encrypt(request.getPassword()));

        entry.setCategory(request.getCategory());
        entry.setNotes(request.getNotes());
        entry.setFavorite(request.isFavorite());
        entry.setUpdatedAt(LocalDateTime.now());

        repo.save(entry);

        return mapToResponse(entry);
    }
@Transactional
    public void deleteEntry(Long id) {
        repo.deleteById(id);
    }

    public List<PasswordEntryResponse> getFavorites(String username)
            throws Exception {

        return repo.findByOwnerUsernameAndFavoriteTrue(username)
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public List<PasswordEntryResponse> search(
            String username, String keyword) throws Exception {

        return repo
                .findByOwnerUsernameAndAccountNameContainingIgnoreCase(
                        username, keyword)
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public List<PasswordEntryResponse> filterByCategory(
            String username, String category) throws Exception {

        return repo.findByOwnerUsernameAndCategory(username, category)
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper().registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());

    public byte[] exportVault(String username, String password) throws Exception {

        List<PasswordEntryResponse> entries = getAllEntries(username);
        String json = objectMapper.writeValueAsString(entries);
        String encrypted = encryptionUtil.encryptWithKey(json, password);
        return encrypted.getBytes();
    }

    @Transactional
    public void importVault(String username, byte[] data, String password) throws Exception {

        String encrypted = new String(data);
        String json = encryptionUtil.decryptWithKey(encrypted, password);
        
        List<PasswordEntryRequest> entries = objectMapper.readValue(json, 
                new com.fasterxml.jackson.core.type.TypeReference<List<PasswordEntryRequest>>() {});

        for (PasswordEntryRequest req : entries) {
            addEntry(username, req);
        }
    }

    private PasswordEntryResponse mapToResponse(
            AllPasswordEntry entry) {

        try {

            return PasswordEntryResponse.builder()
                    .id(entry.getId())
                    .accountName(entry.getAccountName())
                    .website(entry.getWebsite())
                    .username(entry.getUsername())
                    .password(
                            encryptionUtil.decrypt(
                                    entry.getPasswordEncrypted()))
                    .category(entry.getCategory())
                    .notes(entry.getNotes())
                    .favorite(entry.isFavorite())
                    .createdAt(entry.getCreatedAt())
                    .updatedAt(entry.getUpdatedAt())
                    .build();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
