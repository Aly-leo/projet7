import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { TRANSITIONS, type CorrectionStatus } from './models';
import { errorMessage } from './api.service';
import { HttpErrorResponse } from '@angular/common/http';
import { ThemeService } from './theme.service';

describe('Modèles', () => {
  it('un statut final n\'a aucune transition', () => {
    expect(TRANSITIONS.CLOSED).toEqual([]);
    expect(TRANSITIONS.REJECTED).toEqual([]);
  });

  it('chaque transition mène à un statut connu', () => {
    const all = Object.keys(TRANSITIONS) as CorrectionStatus[];
    for (const targets of Object.values(TRANSITIONS)) for (const t of targets) expect(all).toContain(t);
  });
});

describe('errorMessage', () => {
  it('traduit les codes HTTP en messages lisibles, sans détail technique', () => {
    expect(errorMessage(new HttpErrorResponse({ status: 413 }))).toMatch(/volumineux/);
    expect(errorMessage(new HttpErrorResponse({ status: 429 }))).toMatch(/Trop de requêtes/);
    expect(errorMessage(new HttpErrorResponse({ status: 0 }))).toMatch(/injoignable/);
    expect(errorMessage(new HttpErrorResponse({ status: 409, error: { message: 'Déjà importé.' } }))).toBe('Déjà importé.');
    expect(errorMessage(new Error('stack secrète'))).toBe('Une erreur est survenue.');
  });
});

describe('ThemeService', () => {
  it('bascule entre clair et sombre et l\'applique sur la racine', () => {
    TestBed.configureTestingModule({});
    const theme = TestBed.inject(ThemeService);
    TestBed.tick();
    const start = theme.theme();
    theme.toggle();
    TestBed.tick();
    expect(theme.theme()).not.toBe(start);
    expect(document.documentElement.getAttribute('data-theme')).toBe(theme.theme());
  });
});
