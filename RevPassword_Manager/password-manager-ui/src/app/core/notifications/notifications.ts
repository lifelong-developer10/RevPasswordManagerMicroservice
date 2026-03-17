import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { NotificationService, Notification }
from '../services/notification.service';
import { CommonModule } from '@angular/common';
 
@Component({
  selector: 'app-notifications',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './notifications.html',
  styleUrls: ['./notifications.css']
})
export class NotificationsComponent implements OnInit {
 
  notifications: Notification[] = [];
 
  constructor(
    private notificationService: NotificationService,
    private cdr: ChangeDetectorRef
  ) {}
 
  ngOnInit(): void {
    this.loadNotifications();
  }
 
 loadNotifications() {

  const username = localStorage.getItem('username');

  if (!username) {
    console.error("Username not found in localStorage");
    return;
  }

  this.notificationService
    .getNotifications(username)
    .subscribe({
      next: (data) => {

        this.notifications = data;

        // ✅ FIX: unread count bhejo (NOT total)
        const unreadCount = data.filter(n => !n.readStatus).length;

        this.notificationService.setNotificationCount(unreadCount);

        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error("Error fetching notifications", err);
      }
    });
}
 
  markAsRead(id: number) {
  this.notificationService.markAsRead(id).subscribe(() => {

   this.notifications = this.notifications.map(n =>
      n.id === id ? { ...n, readStatus: true } : n
    );

    const unreadCount = this.notifications.filter(n => !n.readStatus).length;

    this.notificationService.setNotificationCount(unreadCount);
      
  
  });
}
 
  deleteNotification(id: number) {
 
    this.notificationService.deleteNotification(id).subscribe(() => {
 
      this.notifications = this.notifications.filter(n => n.id !== id);

    const unreadCount = this.notifications.filter(n => !n.readStatus).length;

    this.notificationService.setNotificationCount(unreadCount);
  
      this.cdr.detectChanges();
    });
  }
 
}
 
