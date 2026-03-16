import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import { RouterModule } from '@angular/router';
import { Component, ViewEncapsulation } from '@angular/core';
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
    private router: Router
  ) {

    this.form = this.fb.group({
      username: ['', Validators.required],
      password: ['', Validators.required]
    });

  }
ngOnInit() {

  this.form.patchValue({
    password: ''
  });

}
logout() {

  localStorage.removeItem('token');

  this.router.navigate(['/login']);
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

  // agar OTP screen already visible, dobara login nahi karna
  if (this.show2FAScreen) return;

  this.auth.login(this.form.value).subscribe({
    next: (res: any) => {
      console.log("LOGIN RESPONSE:", res);

      if (res.token === "OTP_REQUIRED") {
        // OTP backend se aaya → turant screen show
        this.show2FAScreen = true;
        Swal.fire('OTP Sent', 'Check your email', 'info');

        // Username aur password already form me hai, dobara submit nahi karna
        return;
      } else {
        const token = res.token;
        console.log("TOKEN:", token);
        localStorage.setItem("token", token);
        Swal.fire("Login Successful");
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
