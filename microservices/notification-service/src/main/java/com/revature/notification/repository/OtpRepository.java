package com.revature.notification.repository;


import com.revature.notification.models.OTPGenerater;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface OtpRepository extends JpaRepository<OTPGenerater,Long> {
    Optional<OTPGenerater> findTopByOwnerUsernameOrderByExpiryTimeDesc(String ownerUsername);

}
