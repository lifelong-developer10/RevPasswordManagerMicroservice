package com.revature.notification.dtos;

import lombok.Data;

@Data
public class OtpVerifyRequest {

    private String username;
    private String code;

}
