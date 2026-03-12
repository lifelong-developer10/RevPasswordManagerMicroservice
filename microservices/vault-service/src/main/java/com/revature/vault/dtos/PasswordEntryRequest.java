package com.revature.vault.dtos;

import lombok.Data;

@Data
public class PasswordEntryRequest {

    private String accountName;
    private String website;
    private String username;
    private String password;
    private String category;
    private String notes;
    private boolean favorite;

}
