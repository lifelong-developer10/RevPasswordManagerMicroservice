package com.revature.vault.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PasswordEntryRequest {

    @NotBlank(message = "Account name is required")
    @Size(min = 1, max = 100, message = "Account name must be between 1 and 100 characters")
    private String accountName;

    @NotBlank(message = "Website is required")
    @Size(min = 3, max = 255, message = "Website must be between 3 and 255 characters")
    private String website;

    @NotBlank(message = "Username is required")
    @Size(min = 1, max = 100, message = "Username must be between 1 and 100 characters")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 1, max = 255, message = "Password must be at least 1 character")
    private String password;

    @NotBlank(message = "Category is required")
    private String category;

    private String notes;

    private boolean favorite;

}
