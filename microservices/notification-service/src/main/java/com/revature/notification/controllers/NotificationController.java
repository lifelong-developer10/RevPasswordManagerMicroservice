package com.revature.notification.controllers;



import com.revature.notification.dtos.*;
import com.revature.notification.services.NotificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
public class NotificationController {

    private final NotificationService notificationService;

    @GetMapping
    public ResponseEntity<List<NotificationResponse>> getNotifications(
            @RequestParam("username") String username) {

        System.out.println("Username received: " + username);

        return ResponseEntity.ok(notificationService.getNotifications(username));
    }

    @PostMapping("/send")
    public String sendNotification(
            @RequestBody NotificationRequest request) {

        notificationService.sendNotification(request);
        return "Notification sent";
    }

    @PostMapping("/security-alert")
    public String securityAlert(
            @RequestBody SecurityAlertRequest request) {

        notificationService.sendSecurityAlert(request);
        return "Security alert sent";
    }
    @PutMapping("/read/{id}")
    public ResponseEntity<Void> markRead(@PathVariable("id") Long id) {

        notificationService.markAsRead(id);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {

        notificationService.deleteNotification(id);
        return ResponseEntity.ok().build();
    }

}