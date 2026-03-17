package com.revature.notification.dtos;

import lombok.Data;

@Data
public class SecurityAlertRequest {

    private String username;
    private String alertType;
}