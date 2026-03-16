package com.revature.user.repository;

import com.revature.user.models.MasterUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<MasterUser, Long> {
    Optional<MasterUser> findByUsername(String username);


    Optional<MasterUser> findByEmail(String email);

    boolean existsByUsername(String username);
}


