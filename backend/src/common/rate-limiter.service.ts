import { Injectable } from '@nestjs/common';

/**
 * Limiteur de débit à fenêtre glissante, en mémoire.
 * Limite connue : l'état n'est pas partagé entre plusieurs instances (voir docs/DECISIONS.md).
 */
@Injectable()
export class RateLimiterService {
  private readonly hits = new Map<string, number[]>();

  /** Enregistre une requête et indique si elle est autorisée. */
  hit(key: string, limit: number, windowMs: number): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    const recent = (this.hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (recent.length >= limit) {
      this.hits.set(key, recent);
      return { allowed: false, retryAfterSec: Math.max(1, Math.ceil((windowMs - (now - recent[0]!)) / 1000)) };
    }
    recent.push(now);
    this.hits.set(key, recent);
    if (this.hits.size > 50_000) this.prune(now, windowMs);
    return { allowed: true, retryAfterSec: 0 };
  }

  reset(): void {
    this.hits.clear();
  }

  private prune(now: number, windowMs: number): void {
    for (const [k, v] of this.hits) {
      if (v.every((t) => now - t >= windowMs)) this.hits.delete(k);
    }
  }
}
