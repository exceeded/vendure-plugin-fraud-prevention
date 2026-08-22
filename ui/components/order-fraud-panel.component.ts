import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnDestroy, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { UntypedFormGroup } from '@angular/forms';
import { Observable, Subscription } from 'rxjs';
import { CustomDetailComponent, SharedModule } from '@vendure/admin-ui/core';

/**
 * Fraud panel embedded on the admin order-detail page. Shows the risk
 * score, level and contributing signals for the order — but only once
 * the order has actually been paid (a fraud verdict on an unpaid draft
 * is noise). Colours adapt to the admin light/dark theme.
 */
@Component({
    selector: 'hulo-order-fraud-panel',
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true,
    imports: [SharedModule],
    template: `
    <div class="fraud-card" *ngIf="paid && data">
        <div class="fraud-head">
            <span class="fraud-title">🛡 Fraud check</span>
            <span class="score-pill" [class.lvl-low]="levelClass === 'low'" [class.lvl-review]="levelClass === 'review'" [class.lvl-blocked]="levelClass === 'blocked'" *ngIf="data.assessed">
                {{ data.score }}<small>/100</small>
            </span>
            <span class="lvl-label" *ngIf="data.assessed">{{ levelLabel }}</span>
            <span class="lvl-label" *ngIf="!data.assessed">No assessment recorded for this order</span>
        </div>
        <div class="fraud-body" *ngIf="data.assessed">
            <div class="shadow-note" *ngIf="data.action === 'shadow'">
                ⚠️ Scored while fraud protection was <strong>switched off</strong> — no action was taken. Enable protection to hold orders like this.
            </div>
            <div class="case-line" *ngIf="data.case">
                Review case: <strong>{{ data.case.status }}</strong>
                <span class="hint-inline" *ngIf="data.case.status === 'pending'">— this order is waiting in the fraud review queue</span>
            </div>
            <button type="button" class="toggle-btn" (click)="showSignals = !showSignals" *ngIf="data.signals?.length">
                {{ showSignals ? 'Hide' : 'Show' }} {{ data.signals.length }} signal{{ data.signals.length === 1 ? '' : 's' }}
            </button>
            <ul class="signal-list" *ngIf="showSignals">
                <li *ngFor="let s of data.signals">
                    <span class="sig-label">{{ s.label }}</span>
                    <span class="sig-detail">{{ s.detail }}</span>
                    <span class="sig-pts" *ngIf="s.points != null">+{{ s.points }}</span>
                </li>
            </ul>
            <div class="assessed-at" *ngIf="data.assessedAt">Assessed {{ data.assessedAt | date: 'd MMM y, HH:mm' }}</div>
        </div>
    </div>
    `,
    styles: [`
        .fraud-card { margin: 12px 0; padding: 14px 16px; border-radius: 10px; border: 1px solid #e2e8f0; background: #ffffff; font-size: 13px; color: #0f172a; }
        .fraud-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .fraud-title { font-weight: 700; font-size: 13.5px; }
        .score-pill { font-size: 18px; font-weight: 800; padding: 2px 12px; border-radius: 999px; border: 2px solid transparent; }
        .score-pill small { font-size: 11px; font-weight: 600; opacity: .75; }
        .lvl-low { background: #ecfdf5; border-color: #34d399; color: #065f46; }
        .lvl-review { background: #fffbeb; border-color: #fbbf24; color: #92400e; }
        .lvl-blocked { background: #fef2f2; border-color: #f87171; color: #991b1b; }
        .lvl-label { font-weight: 600; color: #475569; }
        .fraud-body { margin-top: 8px; }
        .case-line { margin-bottom: 6px; color: #475569; }
        .hint-inline { color: #94a3b8; }
        .toggle-btn { background: none; border: 1px solid #cbd5e1; border-radius: 7px; padding: 3px 10px; font-size: 12px; cursor: pointer; color: #334155; }
        .toggle-btn:hover { background: #f1f5f9; }
        .signal-list { list-style: none; margin: 8px 0 0; padding: 0; }
        .signal-list li { display: flex; gap: 8px; align-items: baseline; padding: 3px 0; border-bottom: 1px dashed #e2e8f0; }
        .sig-label { font-weight: 600; min-width: 160px; }
        .sig-detail { color: #64748b; flex: 1; }
        .sig-pts { font-weight: 700; color: #b45309; }
        .assessed-at { margin-top: 8px; font-size: 11.5px; color: #94a3b8; }
        .shadow-note { margin: 4px 0 8px; padding: 6px 10px; border-radius: 8px; background: #fffbeb; border: 1px solid #fbbf24; color: #92400e; font-size: 12.5px; }

        :host-context([data-theme='dark']) .fraud-card { background: #1e293b; border-color: #334155; color: #e2e8f0; }
        :host-context([data-theme='dark']) .lvl-label, :host-context([data-theme='dark']) .case-line { color: #94a3b8; }
        :host-context([data-theme='dark']) .lvl-low { background: rgba(52,211,153,.12); color: #6ee7b7; }
        :host-context([data-theme='dark']) .lvl-review { background: rgba(251,191,36,.12); color: #fcd34d; }
        :host-context([data-theme='dark']) .lvl-blocked { background: rgba(248,113,113,.12); color: #fca5a5; }
        :host-context([data-theme='dark']) .toggle-btn { border-color: #475569; color: #cbd5e1; }
        :host-context([data-theme='dark']) .toggle-btn:hover { background: #334155; }
        :host-context([data-theme='dark']) .signal-list li { border-bottom-color: #334155; }
        :host-context([data-theme='dark']) .sig-detail { color: #94a3b8; }
        :host-context([data-theme='dark']) .shadow-note { background: rgba(251,191,36,.12); border-color: #b45309; color: #fcd34d; }
    `],
})
export class OrderFraudPanelComponent implements CustomDetailComponent, OnInit, OnDestroy {
    entity$: Observable<any>;
    detailForm: UntypedFormGroup;

    data: any = null;
    paid = false;
    showSignals = false;
    private sub: Subscription | null = null;
    private loadedForId: string | null = null;

    constructor(private http: HttpClient, private cdr: ChangeDetectorRef) {}

    ngOnInit() {
        this.sub = this.entity$.subscribe(order => {
            if (!order?.id) return;
            // "Paid" = at least one settled payment, or a post-payment state.
            const settled = (order.payments || []).some((p: any) => p.state === 'Settled');
            const paidStates = ['PaymentSettled', 'PartiallyShipped', 'Shipped', 'PartiallyDelivered', 'Delivered'];
            this.paid = settled || paidStates.includes(order.state);
            if (!this.paid || this.loadedForId === String(order.id)) { this.cdr.markForCheck(); return; }
            this.loadedForId = String(order.id);
            this.http.get<any>(`/fraud-prevention/order-assessment/${order.id}`).subscribe({
                next: d => { this.data = d; this.cdr.markForCheck(); },
                error: () => undefined,
            });
        });
    }

    ngOnDestroy() { this.sub?.unsubscribe(); }

    get levelClass(): string {
        const l = String(this.data?.level || '').toLowerCase();
        if (l === 'blocked' || l === 'block') return 'blocked';
        if (l === 'review') return 'review';
        return 'low';
    }

    get levelLabel(): string {
        switch (this.levelClass) {
            case 'blocked': return 'High risk — blocked threshold reached';
            case 'review': return 'Elevated risk — held for review';
            default: return 'Low risk — passed checks';
        }
    }
}
