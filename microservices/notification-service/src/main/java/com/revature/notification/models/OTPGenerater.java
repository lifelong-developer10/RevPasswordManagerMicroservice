package com.revature.notification.models;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data

public class OTPGenerater {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        private String code;
        private LocalDateTime expiryTime;
        private boolean used;

        private String ownerUsername;
    }


