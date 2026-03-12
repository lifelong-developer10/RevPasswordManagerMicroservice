package com.revature.user.security;


import com.revature.user.models.MasterUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    private MasterUser user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // No roles for now (can add ROLE_USER later)
        return Collections.emptyList();
    }

    @Override
    public String getPassword() {
        return user.getPasswordEncrypted();
    }

    @Override
    public String getUsername() {
        return user.getUsername();   // or email if you want login by email
    }

    public Long getId() {
        return user.getId();
    }

    public String getEmail() {
        return user.getEmail();
    }

    public MasterUser getUser() {
        return user;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

