import { createHash } from 'node:crypto';
import sanitizeHtml from 'sanitize-html';
import sjson from 'secure-json-parse';
import { z } from 'zod';

export class ZapImportError extends Error {
  constructor(
    readonly status: 400 | 415 | 422,
    message: string,
  ) {
    super(message);
  }
}

export interface ParsedFinding {
  pluginId: string;
  title: string;
  severity: number;
  confidence: string | null;
  cweId: number | null;
  description: string;
  solution: string | null;
  instancesCount: number;
  sampleUrls: string[];
}

export interface ParseLimits {
  maxAlerts: number;
  maxDepth?: number;
  maxInstancesPerAlert?: number;
}

const MAX_URLS = 50;
const str = (max: number) =>
  z
    .union([z.string(), z.number()])
    .transform((v) => String(v))
    .pipe(z.string().max(max));
const optStr = (max: number) => str(max).optional();
const optInt = (min: number, max: number) =>
  z
    .union([z.string(), z.number()])
    .optional()
    .transform((v) => (v === undefined || v === '' ? undefined : Number(v)))
    .pipe(z.number().int().min(min).max(max).optional());

// Schéma tolérant sur les champs facultatifs (les noms varient selon la version de ZAP), strict sur les types et tailles.
const instanceSchema = z.object({ uri: optStr(2048) });
const alertSchema = z.object({
  pluginid: str(32),
  alert: optStr(300),
  name: optStr(300),
  riskcode: optInt(0, 3),
  confidence: optInt(0, 4),
  riskdesc: optStr(100),
  desc: optStr(100_000),
  solution: optStr(100_000),
  cweid: optInt(-1, 100_000),
  count: optInt(0, 10_000_000),
  instances: z.array(instanceSchema).max(100_000).optional(),
});
const siteSchema = z.object({ alerts: z.array(alertSchema).optional() });
const reportSchema = z.object({ site: z.array(siteSchema).max(100) });

const CONFIDENCE: Record<number, string> = { 0: 'False Positive', 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Confirmed' };

/** Mesure la profondeur d'imbrication JSON sans récursion (texte brut, conscient des chaînes). */
export function jsonDepth(text: string, limit: number): number {
  let depth = 0;
  let max = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 92) i++; // antislash
      else if (c === 34) inString = false;
    } else if (c === 34) inString = true;
    else if (c === 123 || c === 91) {
      if (++depth > max) max = depth;
      if (max > limit) return max;
    } else if (c === 125 || c === 93) depth--;
  }
  return max;
}

/** Convertit du HTML en texte brut : aucune balise n'est conservée, jamais de HTML stocké. */
export function toPlainText(html: string | undefined, maxLen: number): string {
  if (!html) return '';
  const spaced = html.replace(/<(br|\/p|\/div|\/li|\/tr|\/h[1-6])\b[^>]*>/gi, '\n');
  const text = sanitizeHtml(spaced, { allowedTags: [], allowedAttributes: {}, disallowedTagsMode: 'discard' });
  return decodeBasicEntities(text)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/[ \t]+/g, ' ')
    .replace(/\s*\n\s*/g, '\n')
    .trim()
    .slice(0, maxLen);
}

// sanitize-html réencode &, <, > ; on les restitue en texte (affiché ensuite comme texte, jamais comme HTML).
function decodeBasicEntities(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

export function normalizeTitle(title: string): string {
  return title.toLowerCase().replace(/\s+/g, ' ').trim();
}

export function fingerprintOf(applicationId: string, f: Pick<ParsedFinding, 'pluginId' | 'cweId' | 'title'>): string {
  return createHash('sha256')
    .update([applicationId, f.pluginId, f.cweId ?? '', normalizeTitle(f.title)].join('|'))
    .digest('hex');
}

/** Contrôles de format puis analyse sécurisée du rapport (étapes 4 à 8 du pipeline). */
export function parseZapReport(
  file: { originalname: string; mimetype: string; buffer: Buffer },
  limits: ParseLimits,
): { findings: ParsedFinding[]; json: unknown } {
  // Étape 4 : extension, type MIME, premier caractère significatif.
  if (!/\.json$/i.test(file.originalname) || !['application/json', 'text/json'].includes(file.mimetype)) {
    throw new ZapImportError(415, 'Seuls les rapports JSON (.json, application/json) sont acceptés.');
  }
  let text = file.buffer.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  if (text.trimStart()[0] !== '{') throw new ZapImportError(415, 'Le fichier ne ressemble pas à un rapport JSON ZAP.');

  // Étape 5 : profondeur, puis analyse sécurisée (rejet de __proto__ et constructor).
  const maxDepth = limits.maxDepth ?? 20;
  if (jsonDepth(text, maxDepth) > maxDepth) throw new ZapImportError(422, 'Le rapport est trop profondément imbriqué.');
  let json: unknown;
  try {
    json = sjson.parse(text, { protoAction: 'error', constructorAction: 'error' });
  } catch {
    throw new ZapImportError(400, 'JSON invalide ou contenant des clés interdites.');
  }

  // Étape 6 : schéma strict avec plafonds.
  const totalAlerts = countAlerts(json);
  if (totalAlerts > limits.maxAlerts) {
    throw new ZapImportError(422, `Trop d'alertes (maximum ${limits.maxAlerts}).`);
  }
  const parsed = reportSchema.safeParse(json);
  if (!parsed.success) throw new ZapImportError(422, 'Le rapport ne respecte pas le schéma ZAP attendu.');

  // Étapes 7 et 8 : assainissement et normalisation ; fusion des doublons internes au rapport.
  const merged = new Map<string, ParsedFinding>();
  for (const site of parsed.data.site) {
    for (const a of site.alerts ?? []) {
      const title = toPlainText(a.alert ?? a.name ?? '', 300);
      if (!title) throw new ZapImportError(422, "Une alerte n'a pas de titre.");
      const cweId = a.cweid !== undefined && a.cweid > 0 ? a.cweid : null;
      const urls = [...new Set((a.instances ?? []).map((i) => i.uri).filter((u): u is string => !!u))]
        .map((u) => toPlainText(u, 2048))
        .filter(Boolean);
      const finding: ParsedFinding = {
        pluginId: a.pluginid,
        title,
        severity: a.riskcode ?? 0,
        confidence: a.confidence !== undefined ? (CONFIDENCE[a.confidence] ?? null) : null,
        cweId,
        description: toPlainText(a.desc, 2000),
        solution: a.solution ? toPlainText(a.solution, 2000) || null : null,
        instancesCount: Math.max(a.count ?? 0, a.instances?.length ?? 0, 1),
        sampleUrls: urls.slice(0, MAX_URLS),
      };
      const key = `${finding.pluginId}|${finding.cweId ?? ''}|${normalizeTitle(finding.title)}`;
      const prev = merged.get(key);
      if (prev) {
        prev.instancesCount += finding.instancesCount;
        prev.severity = Math.max(prev.severity, finding.severity);
        prev.sampleUrls = [...new Set([...prev.sampleUrls, ...finding.sampleUrls])].slice(0, MAX_URLS);
      } else merged.set(key, finding);
    }
  }
  return { findings: [...merged.values()], json };
}

function countAlerts(json: unknown): number {
  const sites = (json as any)?.site;
  if (!Array.isArray(sites)) return 0;
  let n = 0;
  for (const s of sites) if (Array.isArray(s?.alerts)) n += s.alerts.length;
  return n;
}
