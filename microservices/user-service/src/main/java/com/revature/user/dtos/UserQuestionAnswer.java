package com.revature.user.dtos;

import lombok.Data;

@Data
public class UserQuestionAnswer {

    private Long questionId;
    private String question;
    private String answer;
}
