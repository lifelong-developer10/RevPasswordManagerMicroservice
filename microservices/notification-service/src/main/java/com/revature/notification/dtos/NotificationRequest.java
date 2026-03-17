package com.revature.notification.dtos;

import lombok.Data;

@Data
public class NotificationRequest {

    private String username;
    private String message;
    private String type;

}