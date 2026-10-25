import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';

export interface Query { [key: string]: string | number | boolean | undefined | null }

/** Message d'erreur lisible à partir d'une réponse de l'API (jamais de détail technique). */
export function errorMessage(err: unknown): string {
  if (err instanceof HttpErrorResponse) {
    const m = err.error?.message;
    const text = Array.isArray(m) ? m.join(' ') : typeof m === 'string' ? m : '';
    switch (err.status) {
      case 0: return 'Le serveur est injoignable. Vérifiez votre connexion.';
      case 401: return text || 'Session expirée ou identifiants incorrects.';
      case 403: return text || "Vous n'avez pas le droit d'effectuer cette action.";
      case 404: return text || 'Élément introuvable.';
      case 409: return text || 'Conflit avec l\'état actuel des données.';
      case 413: return 'Le fichier est trop volumineux.';
      case 415: return text || 'Type de fichier non pris en charge.';
      case 422: return text || 'Les données ne sont pas exploitables.';
      case 429: return 'Trop de requêtes. Patientez avant de réessayer.';
      default: return text || 'Une erreur est survenue.';
    }
  }
  return 'Une erreur est survenue.';
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly base = '/api';

  private params(q?: Query): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(q ?? {})) if (v !== undefined && v !== null && v !== '') out[k] = String(v);
    return out;
  }

  get<T>(path: string, q?: Query): Promise<T> {
    return firstValueFrom(this.http.get<T>(`${this.base}${path}`, { params: this.params(q) }));
  }
  post<T>(path: string, body?: unknown): Promise<T> {
    return firstValueFrom(this.http.post<T>(`${this.base}${path}`, body ?? {}));
  }
  put<T>(path: string, body?: unknown): Promise<T> {
    return firstValueFrom(this.http.put<T>(`${this.base}${path}`, body ?? {}));
  }
  delete<T = void>(path: string): Promise<T> {
    return firstValueFrom(this.http.delete<T>(`${this.base}${path}`));
  }
  upload<T>(path: string, form: FormData): Promise<T> {
    return firstValueFrom(this.http.post<T>(`${this.base}${path}`, form));
  }

  /** Téléchargement authentifié d'un PDF : requête avec cookies, blob, puis enregistrement et libération de l'URL d'objet. */
  async downloadPdf(path: string, q?: Query): Promise<void> {
    const res = await firstValueFrom(
      this.http.get(`${this.base}${path}`, { params: this.params(q), responseType: 'blob', observe: 'response' }),
    );
    const blob = res.body as Blob;
    const header = res.headers.get('Content-Disposition') ?? '';
    const match = /filename="([A-Za-z0-9._-]+)"/.exec(header);
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement('a');
      a.href = url;
      a.download = match?.[1] ?? 'rapport.pdf';
      a.rel = 'noopener';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 5_000);
    }
  }
}
