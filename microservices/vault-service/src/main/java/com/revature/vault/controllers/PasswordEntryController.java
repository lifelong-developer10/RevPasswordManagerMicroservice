package com.revature.vault.controllers;

import com.revature.vault.dtos.PasswordEntryRequest;
import com.revature.vault.dtos.PasswordEntryResponse;
import com.revature.vault.models.AllPasswordEntry;
import com.revature.vault.services.PasswordEntryService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
@RestController
@RequestMapping("/api/vault")
@RequiredArgsConstructor
public class PasswordEntryController {

    private final PasswordEntryService service;

    @PostMapping
    public PasswordEntryResponse add(
            @RequestHeader("X-Logged-In-Username") String username,
            @Valid   @RequestBody PasswordEntryRequest request)
            throws Exception {

        return service.addEntry(username, request);
    }

    @GetMapping
    public List<PasswordEntryResponse> getAll(
            @RequestHeader("X-Logged-In-Username") String username)
            throws Exception {

        return service.getAllEntries(username);
    }

    @GetMapping("/{id}")
    public PasswordEntryResponse getOne(@PathVariable Long id)
            throws Exception {

        return service.getEntry(id);
    }

    @PutMapping("/{id}")
    public PasswordEntryResponse update(
            @PathVariable Long id,
            @Valid @RequestBody PasswordEntryRequest request)
            throws Exception {

        return service.updateEntry(id, request);
    }

    @GetMapping("/export/csv")
    public org.springframework.http.ResponseEntity<byte[]> exportCsv(
            @RequestHeader("X-Logged-In-Username") String username) throws Exception {

        byte[] data = service.exportVaultCsv(username);

        return org.springframework.http.ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=vault_export.csv")
                .contentType(org.springframework.http.MediaType.parseMediaType("text/csv"))
                .body(data);
    }

    @GetMapping("/last")
    public PasswordEntryResponse getLast(@RequestHeader("X-Logged-In-Username") String username)
            throws Exception {

        return service.getLastEntry(username);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable("id") Long id) {
        service.deleteEntry(id);
    }

    @GetMapping("/favorites")
    public List<PasswordEntryResponse> favorites(
            @RequestHeader("X-Logged-In-Username") String username)
            throws Exception {

        return service.getFavorites(username);
    }

    @GetMapping("/search")
    public List<PasswordEntryResponse> search(
            @RequestHeader("X-Logged-In-Username") String username,
            @RequestParam String keyword)
            throws Exception {

        return service.search(username, keyword);
    }

    @GetMapping("/category")
    public List<PasswordEntryResponse> filter(
            @RequestHeader("X-Logged-In-Username") String username,
            @RequestParam String category)
            throws Exception {

        return service.filterByCategory(username, category);
    }

    @GetMapping("/export")
    public org.springframework.http.ResponseEntity<byte[]> exportVault(
            @RequestHeader("X-Logged-In-Username") String username,
            @RequestParam String password) throws Exception {

        byte[] data = service.exportVault(username, password);

        return org.springframework.http.ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=vault_export.enc")
                .contentType(org.springframework.http.MediaType.APPLICATION_OCTET_STREAM)
                .body(data);
    }

    @PostMapping("/import")
    public org.springframework.http.ResponseEntity<String> importVault(
            @RequestHeader("X-Logged-In-Username") String username,
            @RequestParam("file") org.springframework.web.multipart.MultipartFile file,
            @RequestParam("password") String password) throws Exception {

        service.importVault(username, file.getBytes(), password);

        return org.springframework.http.ResponseEntity.ok("Vault Imported Successfully");
    }
}
