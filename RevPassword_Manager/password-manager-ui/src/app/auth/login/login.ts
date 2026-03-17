import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { RouterModule } from '@angular/router';
import { Component, ViewEncapsulation } from '@angular/core';
import { NotificationService } from '../../core/services/notification.service';
import { ProfileService } from '../../core/services/profile.service';
import Swal from 'sweetalert2';

@Component({
  selector: 'app-login',
  standalone: true,
  templateUrl: './login.html',
   styleUrls: ['./login.css'],
encapsulation: ViewEncapsulation.None,
  imports: [CommonModule, FormsModule, ReactiveFormsModule,RouterModule]
})
export class LoginComponent {

  show2FAScreen = false;
  twoFACode = '';
showPassword = false;


togglePassword() {
  this.showPassword = !this.showPassword;
}

  form: any;

  constructor(
    private fb: FormBuilder,
    private auth: AuthService,
    private router: Router,
    private notificationService: NotificationService,
    private profileService: ProfileService
    
  ) {

    this.form = this.fb.group({
      username: ['', Validators.required],
      password: ['', Validators.required]
    });

  }
ngOnInit() {

  const savedPassword = localStorage.getItem('generatedPassword');

  if (savedPassword && savedPassword.length >= 8) {
    this.form.patchValue({
      password: savedPassword
    });
  }

}
logout() {

  localStorage.removeItem('token');
 localStorage.removeItem('username');
    localStorage.removeItem('twoFactorEnabled');
  this.router.navigate(['/landing']);
}

verifyLogin2FA() {

  const data = {
    username: this.form.value.username,
    otp: this.twoFACode
  };

  this.auth.verify2FA(data)
    .subscribe({

      next: (res: any) => {

        console.log("OTP RESPONSE:", res);

        if(res.message === "INVALID_OTP"){
          Swal.fire("Invalid OTP");
          return;
        }

        // OTP correct
        localStorage.setItem("token", res.token);

        Swal.fire("Login Successful");

        this.router.navigate(['/dashboard']);

      },

      error: (err) => {

        console.error(err);

        Swal.fire("OTP Verification Failed");

      }

    });


}

login() {
  if (this.form.invalid) return;

  if (this.show2FAScreen) return;

  this.auth.login(this.form.value).subscribe({
    next: (res: any) => {
      console.log("LOGIN RESPONSE:", res);

      if (res.token === "OTP_REQUIRED") {

        this.show2FAScreen = true;

        Swal.fire('OTP Sent', 'Check your email', 'info');
        return;

      } else {

        const token = res.token;
        console.log("TOKEN:", token);

        localStorage.setItem("token", token);

        const username = this.form.value.username;   // ✅ FIX (define kiya)
        localStorage.setItem("username", username);

        Swal.fire("Login Successful");

        // ✅ FIX: notificationService use karne ke liye username pass karo
        this.notificationService.getNotifications(username).subscribe((data: any[]) => {

          const unreadCount = data.filter((n: any) => !n.readStatus).length;

          this.notificationService.setNotificationCount(unreadCount);
        });

        this.profileService.getProfile().subscribe((profile: any) => {
  console.log("PROFILE AFTER LOGIN:", profile);
  const twoFA = profile.twoFactorEnabled ?? false;
  localStorage.setItem("twoFactorEnabled", String(twoFA));

        });

        this.router.navigate(['/dashboard']);
      }
    },
    error: (err) => {
      console.error(err);
      Swal.fire("Login Failed");
    }
  });
}
}