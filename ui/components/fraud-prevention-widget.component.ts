import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { SharedModule } from '@vendure/admin-ui/core';

interface WidgetData {
    tier: 'paid' | 'trial' | 'free';
    notice: { kind: string; message: string; daysLeft: number } | null;
    stats: Array<{ label: string; value: string }>;
    route: string;
}

/**
 * Dashboard widget: three headline figures for the last 7 days, the
 * licence-lifecycle notice when one applies, and a link to the page. Same
 * REST base and admin auth as the main page (plain HttpClient).
 */
@Component({
    selector: 'hulo-fraud-prevention-widget',
    standalone: true,
    imports: [SharedModule],
    changeDetection: ChangeDetectionStrategy.OnPush,
    template: `
        <div class="fp-widget">
            <div class="fp-stats" *ngIf="data; else loadingTpl">
                <div class="fp-stat" *ngFor="let s of data.stats">
                    <div class="fp-num">{{ s.value }}</div>
                    <div class="fp-label">{{ s.label }}</div>
                </div>
            </div>
            <ng-template #loadingTpl>
                <p class="fp-muted">{{ failed ? 'Could not load fraud-prevention figures.' : 'Loading…' }}</p>
            </ng-template>
            <p class="fp-notice" *ngIf="data?.notice">{{ data?.notice?.message }}</p>
            <p class="fp-muted" *ngIf="data">Last 7 days · {{ data.tier === 'paid' ? 'licensed' : data.tier === 'trial' ? 'evaluation' : 'free tier' }}</p>
            <a class="fp-open" [routerLink]="data?.route || '/extensions/fraud-prevention'">Open Fraud Prevention →</a>
        </div>
    `,
    styles: [`
        .fp-widget { display: flex; flex-direction: column; gap: 10px; padding: 4px 2px; }
        .fp-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; }
        .fp-stat { padding: 10px 12px; border-radius: 10px; background: var(--color-component-bg-200, #f2f3f5); border: 1px solid var(--color-component-border-100, #e8eaee); min-width: 0; }
        .fp-num { font-size: 24px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; letter-spacing: -0.02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .fp-label { margin-top: 4px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; color: var(--color-text-300, #5d6470); }
        .fp-notice { margin: 0; padding: 8px 12px; border-radius: 8px; font-size: 12.5px; background: #fffbeb; border: 1px solid #fcd34d; color: #92400e; }
        .fp-muted { margin: 0; font-size: 12px; color: var(--color-text-300, #5d6470); }
        .fp-open { font-size: 13px; font-weight: 600; text-decoration: none; color: #b45309; }
        .fp-open:hover { text-decoration: underline; }
    `],
})
export class FraudPreventionWidgetComponent implements OnInit {
    data: WidgetData | null = null;
    failed = false;

    constructor(private http: HttpClient, private cdr: ChangeDetectorRef) {}

    ngOnInit() {
        this.http.get<WidgetData>('/fraud-prevention/widget').subscribe({
            next: d => { this.data = d; this.cdr.markForCheck(); },
            error: () => { this.failed = true; this.cdr.markForCheck(); },
        });
    }
}
