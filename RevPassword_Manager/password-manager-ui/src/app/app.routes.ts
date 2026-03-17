import { Routes } from '@angular/router';
import { authGuard } from './core/guards/auth-guard';

import { LayoutComponent } from './auth/layout/layout';

import { NotificationsComponent } from './core/notifications/notifications';


export const routes: Routes = [

  {
    path: '',
    loadComponent: () =>
      import('./core/landing/landing')
        .then(m => m.LandingComponent)
  },

  // ================= AUTH PAGES =================

  { path: '', redirectTo: 'login', pathMatch: 'full' },

  {
    path: 'login',
    loadComponent: () =>
      import('./auth/login/login')
        .then(m => m.LoginComponent)
  },

  {
    path: 'register',
    loadComponent: () =>
      import('./auth/register/register')
        .then(m => m.RegisterComponent)
  },

  {
    path: 'forgot-password',
    loadComponent: () =>
      import('./auth/forgot-password/forgot-password')
        .then(m => m.ForgotPasswordComponent)
  },


  // ================= MAIN APP (WITH SIDEBAR) =================

  {
    path: '',
    component: LayoutComponent,
    canActivate: [authGuard],
    children: [

      {
        path: 'dashboard',
        loadComponent: () =>
          import('./dashboard/dashboard')
            .then(m => m.DashboardComponent)
      },

      {
        path: 'vault',
        loadComponent: () =>
          import('./vault/vault')
            .then(m => m.VaultComponent)
      },

      {
        path: 'profile',
        loadComponent: () =>
          import('./profile/profile')
            .then(m => m.ProfileComponent)
      },

      {
        path: 'generator',
        loadComponent: () =>
          import('./generator/generator')
            .then(m => m.GeneratorComponent)
      },

       {
  path: 'notifications',
  loadComponent: () =>
    import('./core/notifications/notifications')
      .then(m => m.NotificationsComponent)
}

    ]
  }

];
