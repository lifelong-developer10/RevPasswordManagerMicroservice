import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../core/services/auth.service';
import Swal from 'sweetalert2';
@Component({
  selector: 'app-register',
  standalone: true,
  templateUrl: './register.html',
   styleUrls: ['./register.css'],
  imports: [CommonModule, FormsModule, ReactiveFormsModule ]
})
export class RegisterComponent implements OnInit {

  form: any;

  showPassword = false;

  // ===== Security Questions =====
  questions: any[] = [];

  // ===== Password Strength =====
  strengthScore = 0;
  strengthLabel = '';
  strengthColor = 'red';

  constructor(
    private fb: FormBuilder,
    private auth: AuthService,
    private router: Router
  ) {

    this.form = this.fb.group({

      username: ['', [Validators.required, Validators.minLength(3)]],

      email: ['', [
        Validators.required,
        Validators.pattern(/^[a-zA-Z0-9._%+-]+@gmail\.com$/)
      ]],

      phone: ['', [
        Validators.required,
        Validators.pattern(/^[0-9]{10}$/)
      ]],

      password: ['', [
        Validators.required,
        Validators.minLength(8)
      ]]

    });

  }

  // ================= INIT =================


ngOnInit() {
  this.loadQuestions();
}

  // ================= LOAD QUESTIONS =================

 loadQuestions() {
   this.auth.getQuestions().subscribe((res: any[]) => {

     this.questions = res
       .sort(() => 0.5 - Math.random())
       .slice(0, 3)
       .map(q => ({
         id: q.id,              // ✅ ensure id stored
         question: q.question,
         answer: ''
       }));

     console.log('QUESTIONS LOADED', this.questions);
   });
 }

 goToLogin() {
  this.router.navigate(['/login']);
}
  // ================= Toggle Password =================

  togglePassword() {
    this.showPassword = !this.showPassword;
  }

  // ================= Password Strength =================

  checkStrength() {

    const password = this.form.get('password')?.value || '';

    let score = 0;

    if (password.length >= 8) score += 25;
    if (/[A-Z]/.test(password)) score += 25;
    if (/[0-9]/.test(password)) score += 25;
    if (/[^A-Za-z0-9]/.test(password)) score += 25;

    this.strengthScore = score;

    if (score <= 25) {
      this.strengthLabel = 'Weak';
      this.strengthColor = 'red';
    } else if (score <= 50) {
      this.strengthLabel = 'Medium';
      this.strengthColor = 'orange';
    } else if (score <= 75) {
      this.strengthLabel = 'Strong';
      this.strengthColor = 'blue';
    } else {
      this.strengthLabel = 'Very Strong';
      this.strengthColor = 'green';
    }

  }
step = 1;

nextStep() {

  if (this.form.invalid) {
    Swal.fire('Please fill all required fields');
    return;
  }

  this.step = 2;
}
  // ================= Password Generator =================

  generatePassword() {

    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';

    let password = '';

    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

     this.form.controls['password'].setValue(password); 

  
  this.checkStrength();

  

 
  this.showPassword = true;

    this.form.patchValue({
      password: password
    });


    this.checkStrength();
  }

  // ================= REGISTER =================
register() {

   if (this.form.invalid) {
     Swal.fire('Please fill all required fields');
     return;
   }

   const allAnswered = this.questions.every(q => q.answer && q.answer.trim().length > 0);
   if (!allAnswered) {
  Swal.fire('Please answer all 3 security questions');
     return;
   }

   const payload = {
     ...this.form.value,
     securityAnswers: this.questions.map(q => ({
       questionId: q.id,
       answer: q.answer
     }))
   };

   console.log('REGISTER PAYLOAD', payload);

   this.auth.register(payload).subscribe({
     next: () => {
         localStorage.removeItem('generatedPassword');
      Swal.fire('Registration successful');
       this.router.navigate(['/login']);
     },
     error: (err) => {
       console.error(err);
       Swal.fire(err.error?.error || 'Registration failed');
     }
   });
 }
  // ================= LOGOUT =================

 logout() {

   localStorage.removeItem('token');

   this.router.navigate(['/login']);
 }
}
