import { ChangeDetectionStrategy, Component, DestroyRef, ElementRef, effect, inject, input, viewChild } from '@angular/core';
import {
  ArcElement, BarController, BarElement, CategoryScale, Chart, ChartConfiguration, DoughnutController, Legend, LinearScale, Tooltip,
} from 'chart.js';
import { ThemeService } from '../core/theme.service';

Chart.register(ArcElement, BarController, BarElement, CategoryScale, DoughnutController, Legend, LinearScale, Tooltip);

const cssVar = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/** Graphique Chart.js qui suit le thème (couleurs lues dans les variables CSS) et se redessine au changement. */
@Component({
  selector: 'app-chart',
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: `:host { display: block; position: relative; height: var(--h, 260px); }`,
  template: `<canvas #canvas role="img" [attr.aria-label]="label()"></canvas>`,
})
export class ChartComponent {
  readonly type = input.required<'bar' | 'doughnut'>();
  readonly labels = input.required<string[]>();
  readonly values = input.required<number[]>();
  readonly colors = input.required<string[]>(); // noms de variables CSS, ex. '--p1'
  readonly label = input('Graphique');
  readonly horizontal = input(false);

  private readonly canvas = viewChild.required<ElementRef<HTMLCanvasElement>>('canvas');
  private readonly theme = inject(ThemeService);
  private chart?: Chart;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.chart?.destroy());
    effect(() => {
      this.theme.version();
      const type = this.type();
      const labels = this.labels();
      const values = this.values();
      const colors = this.colors().map((c) => cssVar(c) || '#7a8aa6');
      const text = cssVar('--text-soft');
      const grid = cssVar('--chart-grid');
      this.chart?.destroy();
      const config = {
        type,
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors,
            borderWidth: type === 'doughnut' ? 2 : 0,
            borderColor: cssVar('--bg') || '#fff',
            borderRadius: type === 'bar' ? 8 : 0,
            maxBarThickness: 38,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: this.horizontal() ? 'y' : 'x',
          cutout: type === 'doughnut' ? '68%' : undefined,
          plugins: {
            legend: { display: type === 'doughnut', position: 'bottom', labels: { color: text, usePointStyle: true, boxWidth: 8 } },
            tooltip: { padding: 10, cornerRadius: 10 },
          },
          scales: type === 'bar'
            ? {
                x: { grid: { display: false }, ticks: { color: text }, border: { display: false } },
                y: { grid: { color: grid }, ticks: { color: text, precision: 0 }, border: { display: false }, beginAtZero: true },
              }
            : undefined,
        },
      };
      this.chart = new Chart(this.canvas().nativeElement, config as unknown as ChartConfiguration);
    });
  }
}
