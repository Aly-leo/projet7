import { fileURLToPath } from 'node:url';
import PDFDocument from 'pdfkit';

const FONT_REGULAR = new URL('../../assets/fonts/NotoSans-Regular.ttf', import.meta.url);
const FONT_BOLD = new URL('../../assets/fonts/NotoSans-Bold.ttf', import.meta.url);

const COLORS = { ink: '#1b2540', muted: '#5b6785', line: '#d5deeb', accent: '#2f6fb3', soft: '#eaf1fa', P1: '#b3261e', P2: '#c2570c', P3: '#2f6fb3', P4: '#7a8aa6' } as const;

export class PdfLimitError extends Error {}

/** Texte inerte : caractères de contrôle retirés, longueur bornée. Jamais de balisage interprété. */
export function clean(value: unknown, max = 200): string {
  const s = String(value ?? '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F‪-‮⁦-⁩]/g, '')
    .trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

export interface Column {
  header: string;
  width: number;
  align?: 'left' | 'right' | 'center';
}

/** Fine surcouche de pdfkit : police embarquée, aucune image, aucun lien, aucun script, aucun formulaire. */
export class ReportPdf {
  readonly doc: InstanceType<typeof PDFDocument>;
  private readonly chunks: Buffer[] = [];
  private readonly left = 50;
  private readonly contentWidth: number;
  private readonly bottom = 60;

  constructor(
    title: string,
    private readonly maxPages: number,
  ) {
    this.doc = new PDFDocument({
      size: 'A4',
      margins: { top: 50, bottom: this.bottom, left: 50, right: 50 },
      bufferPages: true,
      font: fileURLToPath(FONT_REGULAR),
      info: { Title: clean(title, 120), Subject: 'Rapport de priorisation des vulnérabilités (prédictions simulées)', Creator: 'Projet 7 – prototype' },
    });
    this.doc.registerFont('Bold', this.fontPath(FONT_BOLD));
    this.doc.registerFont('Regular', this.fontPath(FONT_REGULAR));
    this.contentWidth = this.doc.page.width - 100;
    this.doc.on('data', (c: Buffer) => this.chunks.push(c));
  }

  private fontPath(u: URL): string {
    return fileURLToPath(u);
  }

  private ensure(height: number): void {
    if (this.doc.y + height > this.doc.page.height - this.bottom) this.doc.addPage();
    if (this.doc.bufferedPageRange().count > this.maxPages) throw new PdfLimitError('Plafond de pages dépassé.');
  }

  cover(opts: { title: string; subtitle: string; lines: [string, string][] }): void {
    const d = this.doc;
    d.rect(0, 0, d.page.width, 170).fill(COLORS.soft);
    d.fillColor(COLORS.ink).font('Bold').fontSize(26).text(clean(opts.title, 120), this.left, 70, { width: this.contentWidth });
    d.font('Regular').fontSize(13).fillColor(COLORS.muted).text(clean(opts.subtitle, 160), this.left, d.y + 6, { width: this.contentWidth });
    d.y = 200;
    d.roundedRect(this.left, d.y, this.contentWidth, 34, 6).fill('#fff4e5');
    d.fillColor('#8a4b08').font('Bold').fontSize(12).text('Prédictions simulées', this.left + 14, d.y + 10, { width: this.contentWidth - 28 });
    d.y += 52;
    for (const [k, v] of opts.lines) {
      d.font('Bold').fontSize(10).fillColor(COLORS.muted).text(k.toUpperCase(), this.left, d.y, { width: 140, continued: false });
      d.font('Regular').fontSize(11).fillColor(COLORS.ink).text(clean(v, 200), this.left + 150, d.y - 12, { width: this.contentWidth - 150 });
      d.moveDown(0.8);
    }
    d.addPage();
  }

  heading(text: string, level: 1 | 2 = 1): void {
    this.ensure(level === 1 ? 60 : 40);
    const d = this.doc;
    d.moveDown(level === 1 ? 0.6 : 0.3);
    d.font('Bold').fontSize(level === 1 ? 16 : 12.5).fillColor(level === 1 ? COLORS.ink : COLORS.accent).text(clean(text, 160), this.left, d.y, { width: this.contentWidth });
    if (level === 1) {
      d.moveTo(this.left, d.y + 2).lineTo(this.left + this.contentWidth, d.y + 2).strokeColor(COLORS.line).lineWidth(1).stroke();
      d.moveDown(0.5);
    } else d.moveDown(0.2);
  }

  paragraph(text: string, opts: { size?: number; color?: string; max?: number } = {}): void {
    const t = clean(text, opts.max ?? 2000);
    if (!t) return;
    const d = this.doc;
    d.font('Regular').fontSize(opts.size ?? 10).fillColor(opts.color ?? COLORS.ink);
    this.ensure(d.heightOfString(t, { width: this.contentWidth }) + 6);
    d.text(t, this.left, d.y, { width: this.contentWidth });
    d.moveDown(0.4);
  }

  keyValues(rows: [string, string][]): void {
    for (const [k, v] of rows) {
      this.ensure(18);
      const y = this.doc.y;
      this.doc.font('Bold').fontSize(9.5).fillColor(COLORS.muted).text(clean(k, 60), this.left, y, { width: 150 });
      this.doc.font('Regular').fontSize(10).fillColor(COLORS.ink).text(clean(v, 300), this.left + 160, y, { width: this.contentWidth - 160 });
      this.doc.y = Math.max(this.doc.y, y + 15);
    }
    this.doc.moveDown(0.3);
  }

  /** Graphique en barres vectoriel (rectangles uniquement). */
  barChart(data: { label: string; value: number; color?: string }[]): void {
    const d = this.doc;
    const max = Math.max(1, ...data.map((x) => x.value));
    this.ensure(data.length * 24 + 10);
    for (const row of data) {
      const y = d.y;
      d.font('Regular').fontSize(10).fillColor(COLORS.ink).text(clean(row.label, 40), this.left, y + 3, { width: 110 });
      const w = Math.max(row.value > 0 ? 2 : 0, ((this.contentWidth - 180) * row.value) / max);
      d.roundedRect(this.left + 120, y + 2, this.contentWidth - 180, 14, 3).fill(COLORS.soft);
      if (w > 0) d.roundedRect(this.left + 120, y + 2, w, 14, 3).fill(row.color ?? COLORS.accent);
      d.font('Bold').fontSize(10).fillColor(COLORS.ink).text(String(row.value), this.left + this.contentWidth - 50, y + 3, { width: 50, align: 'right' });
      d.y = y + 22;
    }
    d.moveDown(0.3);
  }

  table(columns: Column[], rows: string[][], opts: { priorityCol?: number } = {}): void {
    const d = this.doc;
    const total = columns.reduce((a, c) => a + c.width, 0);
    const scale = this.contentWidth / total;
    const widths = columns.map((c) => c.width * scale);
    const drawHeader = () => {
      const y = d.y;
      d.rect(this.left, y, this.contentWidth, 20).fill(COLORS.ink);
      let x = this.left;
      columns.forEach((c, i) => {
        d.font('Bold').fontSize(8.5).fillColor('#ffffff').text(c.header, x + 4, y + 6, { width: widths[i]! - 8, align: c.align ?? 'left', lineBreak: false });
        x += widths[i]!;
      });
      d.y = y + 22;
    };
    this.ensure(60);
    drawHeader();
    rows.forEach((row, r) => {
      d.font('Regular').fontSize(8.5);
      const heights = row.map((cell, i) => d.heightOfString(clean(cell, 200), { width: widths[i]! - 8 }));
      const h = Math.max(16, ...heights) + 6;
      if (d.y + h > d.page.height - this.bottom) {
        d.addPage();
        if (d.bufferedPageRange().count > this.maxPages) throw new PdfLimitError('Plafond de pages dépassé.');
        drawHeader();
      }
      const y = d.y;
      if (r % 2 === 1) d.rect(this.left, y, this.contentWidth, h).fill('#f5f8fc');
      let x = this.left;
      row.forEach((cell, i) => {
        const isPrio = opts.priorityCol === i && /^P[1-4]$/.test(cell);
        d.font(isPrio ? 'Bold' : 'Regular').fontSize(8.5).fillColor(isPrio ? COLORS[cell as 'P1'] : COLORS.ink)
          .text(clean(cell, 200), x + 4, y + 3, { width: widths[i]! - 8, align: columns[i]!.align ?? 'left' });
        x += widths[i]!;
      });
      d.y = y + h;
    });
    d.moveDown(0.5);
  }

  card(title: string, priority: string, body: (p: ReportPdf) => void): void {
    this.ensure(110);
    const d = this.doc;
    const y = d.y;
    d.roundedRect(this.left, y, this.contentWidth, 24, 5).fill(COLORS.soft);
    d.font('Bold').fontSize(10).fillColor(COLORS[(priority as 'P1') in COLORS ? (priority as 'P1') : 'P4']).text(priority || '–', this.left + 10, y + 7, { width: 30, lineBreak: false });
    d.font('Bold').fontSize(10.5).fillColor(COLORS.ink).text(clean(title, 200), this.left + 44, y + 6, { width: this.contentWidth - 54, height: 14, ellipsis: true });
    d.y = y + 30;
    body(this);
    d.moveDown(0.6);
  }

  /** Barres de contribution centrées sur zéro (explication de type SHAP simulée). */
  contributions(items: { feature: string; contribution: number }[]): void {
    const d = this.doc;
    const mid = this.left + 150 + (this.contentWidth - 150) / 2;
    const half = (this.contentWidth - 150) / 2 - 30;
    for (const it of items) {
      this.ensure(16);
      const y = d.y;
      d.font('Regular').fontSize(8.5).fillColor(COLORS.muted).text(clean(it.feature, 40), this.left, y + 2, { width: 145 });
      const w = Math.min(1, Math.abs(it.contribution)) * half;
      d.rect(it.contribution >= 0 ? mid : mid - w, y + 2, Math.max(w, 1), 9).fill(it.contribution >= 0 ? COLORS.accent : COLORS.P2);
      d.font('Regular').fontSize(8).fillColor(COLORS.ink).text(it.contribution.toFixed(2), this.left + this.contentWidth - 40, y + 2, { width: 40, align: 'right', lineBreak: false });
      d.y = y + 14;
    }
  }

  /** Termine le document : pied de page « Rapport généré le … · Simulation · page n/N ». */
  async finish(generatedAt: string): Promise<Buffer> {
    const d = this.doc;
    const range = d.bufferedPageRange();
    if (range.count > this.maxPages) throw new PdfLimitError('Plafond de pages dépassé.');
    for (let i = 0; i < range.count; i++) {
      d.switchToPage(range.start + i);
      const prevBottom = d.page.margins.bottom;
      d.page.margins.bottom = 0;
      d.font('Regular').fontSize(8).fillColor(COLORS.muted).text(
        `Rapport généré le ${generatedAt} · Simulation · page ${i + 1}/${range.count}`,
        this.left,
        d.page.height - 38,
        { width: this.contentWidth, align: 'center', lineBreak: false },
      );
      d.page.margins.bottom = prevBottom;
    }
    return new Promise<Buffer>((resolve, reject) => {
      d.on('end', () => resolve(Buffer.concat(this.chunks)));
      d.on('error', reject);
      d.end();
    });
  }
}
