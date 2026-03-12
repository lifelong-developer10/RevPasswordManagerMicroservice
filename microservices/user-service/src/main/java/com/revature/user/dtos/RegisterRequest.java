package com.revature.user.dtos;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class RegisterRequest {

    private String username;
    private String email;
    private String phone;
    private String password;

    @JsonProperty("securityAnswers")
    @Size(min = 3, message = "At least 3 security questions must be provided")
    private List<UserQuestionAnswer> securityAnswers;
}
