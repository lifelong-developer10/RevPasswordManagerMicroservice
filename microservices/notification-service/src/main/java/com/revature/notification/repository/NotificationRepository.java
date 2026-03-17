package com.revature.notification.repository;

import com.revature.notification.models.Notification;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface NotificationRepository
        extends JpaRepository<Notification, Long> {

    List<Notification> findByUsername(String username);

    List<Notification> findByUsernameAndReadStatusFalse(String username);

}