import { Injectable, signal } from '@angular/core';

export interface Toast { id: number; kind: 'ok' | 'error' | 'info'; text: string }

@Injectable({ providedIn: 'root' })
export class ToastService {
  readonly toasts = signal<Toast[]>([]);
  private seq = 0;

  show(kind: Toast['kind'], text: string, ms = 5000): void {
    const id = ++this.seq;
    this.toasts.update((t) => [...t.slice(-3), { id, kind, text }]);
    setTimeout(() => this.dismiss(id), ms);
  }
  ok(text: string): void { this.show('ok', text); }
  error(text: string): void { this.show('error', text, 7000); }
  dismiss(id: number): void { this.toasts.update((t) => t.filter((x) => x.id !== id)); }
}
