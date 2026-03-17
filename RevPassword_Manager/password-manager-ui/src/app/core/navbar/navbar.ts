import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { NotificationService } from '../services/notification.service';

@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './navbar.html',
  styleUrls: ['./navbar.css']
})
export class NavbarComponent implements OnInit {

  notificationCount: number = 0;

  constructor(
    private router: Router,
    private notificationService: NotificationService
  ) {}

 ngOnInit(): void {
  this.notificationService.notificationCount$.subscribe(count => {
    this.notificationCount = count || 0;
  });
  }

  goDashboard() {
    this.router.navigateByUrl('/dashboard');
  }

  goProfile() {
    this.router.navigate(['/profile']);
  }

  goVault() {
    this.router.navigateByUrl('/vault');
  }

  goNotifications() {
    this.router.navigate(['/notifications']).then(() => {
      window.scrollTo(0, 0);
    });
  }

  logout() {
    localStorage.removeItem('token');
    this.router.navigate(['/login']);
  }
}