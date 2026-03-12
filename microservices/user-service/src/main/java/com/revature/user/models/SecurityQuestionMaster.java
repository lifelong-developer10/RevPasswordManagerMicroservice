package com.revature.user.models;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "security_question_master")
@Data
public class SecurityQuestionMaster {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String question;
}
