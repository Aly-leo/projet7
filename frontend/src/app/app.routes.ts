import { Routes } from '@angular/router';
import { authGuard, guestGuard, installationGuard, roleGuard } from './core/guards';
import { ShellComponent } from './shared/shell.component';

const STAFF = ['ADMIN', 'ANALYST'] as const;

export const routes: Routes = [
  {
    path: '',
    canActivateChild: [installationGuard],
    children: [
      {
        path: 'installation',
        loadComponent: () => import('./features/install.page').then((m) => m.InstallPage),
        title: 'Installation',
      },
      {
        path: 'connexion',
        canActivate: [guestGuard],
        loadComponent: () => import('./features/login.page').then((m) => m.LoginPage),
        title: 'Connexion',
      },
      {
        path: 'changer-mot-de-passe',
        canActivate: [authGuard],
        loadComponent: () => import('./features/change-password.page').then((m) => m.ChangePasswordPage),
        title: 'Changer le mot de passe',
      },
      {
        path: '',
        component: ShellComponent,
        canActivate: [authGuard],
        children: [
          { path: '', pathMatch: 'full', redirectTo: 'tableau-de-bord' },
          { path: 'tableau-de-bord', loadComponent: () => import('./features/dashboard.page').then((m) => m.DashboardPage), title: 'Tableau de bord' },
          { path: 'import', canActivate: [roleGuard(...STAFF)], loadComponent: () => import('./features/import.page').then((m) => m.ImportPage), title: 'Importer un scan' },
          { path: 'constats', canActivate: [roleGuard(...STAFF)], loadComponent: () => import('./features/findings.page').then((m) => m.FindingsPage), title: 'Constats' },
          { path: 'constats/:id', canActivate: [roleGuard(...STAFF)], loadComponent: () => import('./features/finding-detail.page').then((m) => m.FindingDetailPage), title: 'Détail du constat' },
          { path: 'applications', canActivate: [roleGuard(...STAFF)], loadComponent: () => import('./features/applications.page').then((m) => m.ApplicationsPage), title: 'Applications' },
          { path: 'utilisateurs', canActivate: [roleGuard('ADMIN')], loadComponent: () => import('./features/users.page').then((m) => m.UsersPage), title: 'Utilisateurs' },
          { path: 'modeles', canActivate: [roleGuard('ADMIN')], loadComponent: () => import('./features/models.page').then((m) => m.ModelsPage), title: 'Modèles' },
          { path: 'audit', canActivate: [roleGuard('ADMIN')], loadComponent: () => import('./features/audit.page').then((m) => m.AuditPage), title: "Journal d'audit" },
          { path: 'rapports', loadComponent: () => import('./features/reports.page').then((m) => m.ReportsPage), title: 'Rapports' },
          { path: '403', loadComponent: () => import('./features/errors.page').then((m) => m.ForbiddenPage), title: 'Accès refusé' },
          { path: '**', loadComponent: () => import('./features/errors.page').then((m) => m.NotFoundPage), title: 'Page introuvable' },
        ],
      },
    ],
  },
];
