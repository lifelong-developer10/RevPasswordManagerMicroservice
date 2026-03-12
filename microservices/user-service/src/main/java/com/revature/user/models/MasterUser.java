package com.revature.user.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.stream.Collectors;

import java.util.List;

@Entity
@Table(name = "master_user")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MasterUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String username;
    private String email;
    private String phone;

    @Column(name = "password_encrypted")
    private String passwordEncrypted;

    @Column(name = "two_factor_enabled")
    private boolean twoFactorEnabled;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<SecurityQuestions> securityQuestions;

    public void setId(Long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public void setPasswordEncrypted(String passwordEncrypted) {
        this.passwordEncrypted = passwordEncrypted;
    }

    public void setTwoFactorEnabled(boolean twoFactorEnabled) {
        this.twoFactorEnabled = twoFactorEnabled;
    }

    public void setSecurityQuestions(List<SecurityQuestions> securityQuestions) {
        this.securityQuestions = securityQuestions;
    }
}
