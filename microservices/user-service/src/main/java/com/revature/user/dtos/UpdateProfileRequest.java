package com.revature.user.dtos;

import lombok.Data;

@Data
public class UpdateProfileRequest {

    private String email;
    private String phone;

}

