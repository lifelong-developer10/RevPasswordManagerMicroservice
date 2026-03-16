package com.revature.user.dtos;

import lombok.Data;

@Data
public class OtpRequest {

    private String username;
    private String otp;

}