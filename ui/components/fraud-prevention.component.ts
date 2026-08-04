import { Component, OnInit, ChangeDetectorRef, ViewChild, ElementRef } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { NotificationService, ModalService, AssetPickerDialogComponent } from '@vendure/admin-ui/core';

interface FraudConfig {
    channelId: number;
    channelCode?: string;
    enabled: boolean;
    mode: 'off' | 'monitor' | 'enforce';
    reviewThreshold: number;
    blockThreshold: number;
    holdFulfilment: boolean;
    maxOrdersPerIpPerHour: number;
    maxOrdersPerIpPerDay: number;
    maxOrdersPerEmailPerDay: number;
    maxDailyValuePerEmailPence: number;
    maxOrderValuePence: number;
    requireEmailVerificationAbovePence: number;
    blockDisposableEmails: boolean;
    blockVpnProxy: boolean;
    blockHighRiskCountries: boolean;
    highRiskCountries: string;
    enforce3dSecure: boolean;
    maxFailedPaymentsPerIpPerHour: number;
    cooldownMinutesAfterFailedPayment: number;
    autoApproveAfterHours: number;
    notifyCustomerOnHold: 'never' | 'block' | 'always';
    reviewHours: number;
    signalWeights: Record<string, number>;
}

type Tab = 'overview' | 'rules' | 'review' | 'lists' | 'simulate' | 'lookup' | 'activity' | 'settings';

@Component({
    selector: 'hulo-fraud-prevention',
    standalone: false,
    template: `
        <!-- ── HULO brand hero ─────────────────────────────────────── -->
        <vdr-page-block>
            <div class="hulo-hero">
                <div class="hulo-hero-logo" aria-hidden="true">
                    <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
                        <rect width="64" height="64" rx="14" fill="#0f1419"/>
                        <path d="M32 9 L51 16.5 V30.5 C51 43.5 43 52.5 32 56 C21 52.5 13 43.5 13 30.5 V16.5 Z" fill="none" stroke="#ffffff" stroke-width="2.6" stroke-linejoin="round"/>
                        <polyline points="17,33 24.5,33 27.5,25 32.5,41 36,29 38.5,33 47,33" fill="none" stroke="#f59e0b" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"/>
                        <circle cx="47" cy="33" r="2.6" fill="#f59e0b"/>
                    </svg>
                </div>
                <div class="hulo-hero-text">
                    <h2 class="hulo-hero-title">Fraud prevention</h2>
                    <p class="hulo-hero-sub">Every order is risk-scored the moment it's placed — velocity, disposable emails, threat feeds, failed payments and more. You decide the thresholds; risky orders wait for your approval before licence keys go out.</p>
                </div>
                <div class="hulo-hero-actions">
                    <button class="gbtn gbtn-hero" (click)="helpOpen = !helpOpen" [attr.aria-expanded]="helpOpen">
                        <clr-icon shape="help"></clr-icon> Help
                    </button>
                    <button class="gbtn gbtn-hero" (click)="reloadAll()" [disabled]="loading">
                        <clr-icon shape="refresh"></clr-icon> Refresh
                    </button>
                </div>
            </div>
        </vdr-page-block>

        <vdr-page-block *ngIf="helpOpen">
            <div class="hulo-help-drawer">
                <div class="hulo-help-grid">
                    <div class="hulo-help-card">
                        <div class="hulo-help-num">1</div>
                        <h4>Pick a mode</h4>
                        <p><strong>Monitor</strong> scores and logs every order but never interferes — start here and watch the Activity tab. <strong>Enforce</strong> holds risky orders for manual review before fulfilment.</p>
                    </div>
                    <div class="hulo-help-card">
                        <div class="hulo-help-num">2</div>
                        <h4>Tune the thresholds</h4>
                        <p>Each fired signal adds points. At the review threshold an order is held; at the block threshold the customer is told it's being verified. Use Simulate to test before enforcing.</p>
                    </div>
                    <div class="hulo-help-card">
                        <div class="hulo-help-num">3</div>
                        <h4>Work the queue</h4>
                        <p>Held orders appear in Review. Approve releases the licence keys and emails the customer; Reject cancels and notifies them. Everything is written to the audit log.</p>
                    </div>
                </div>
                <div class="hulo-help-links">
                    <a href="https://huloglobal.com/vendure-plugins/fraud-prevention/docs/" target="_blank">Full docs ↗</a>
                    <a href="https://huloglobal.com/vendure-plugins/fraud-prevention/" target="_blank">Plugin page ↗</a>
                    <a href="mailto:support@huloglobal.com">Email support</a>
                </div>
            </div>
        </vdr-page-block>

        <!-- Licence + update banners -->
        <vdr-page-block *ngIf="meta && !meta.licensed">
            <div class="update-banner major">
                <div>
                    <strong>🔓 Free tier</strong> — monitoring, manual lists and simulate are active. Enforce mode,
                    review-queue holds, threat-feed sync and email alerts need a licence.
                </div>
                <div class="actions">
                    <a href="https://huloglobal.com/vendure-plugins/fraud-prevention/" target="_blank" class="gbtn gbtn-primary gbtn-sm">Get a licence ↗</a>
                </div>
            </div>
        </vdr-page-block>
        <vdr-page-block *ngIf="updateAvailable()">
            <div class="update-banner">
                <div>
                    <strong>📦 Update available</strong>
                    <!--email_off-->{{ meta.name }} {{ meta.version }} → <strong>{{ meta.update.latest }}</strong><!--/email_off-->
                </div>
                <div class="actions">
                    <button class="gbtn gbtn-outline gbtn-sm" (click)="meta.update = null">Dismiss</button>
                </div>
            </div>
        </vdr-page-block>

        <!-- ── Top bar: channel, mode, status sentence, tabs ────────── -->
        <vdr-page-block *ngIf="!loading && current">
            <div class="card top-bar">
                <div class="card-block">
                    <div class="chan-row">
                        <label class="lbl">Channel</label>
                        <select class="form-select" [(ngModel)]="currentIdx" (ngModelChange)="onChannelChange()">
                            <option *ngFor="let c of configs; let i = index" [ngValue]="i">{{ c.channelCode }}</option>
                        </select>

                        <span class="mode-seg" role="radiogroup" aria-label="Enforcement mode">
                            <button *ngFor="let m of modes" class="seg" role="radio"
                                    [attr.aria-checked]="current.mode === m.key"
                                    [class.active]="current.mode === m.key"
                                    [class.seg-enforce]="m.key === 'enforce' && current.mode === m.key"
                                    (click)="setMode(m.key)">{{ m.label }}</button>
                        </span>

                        <span class="dirty-flag" *ngIf="dirty">● Unsaved</span>
                    </div>

                    <p class="status-sentence" [class.status-off]="current.mode === 'off'" [class.status-danger]="current.mode === 'enforce'">
                        {{ statusSentence() }}
                    </p>

                    <div class="tabs" role="tablist" aria-label="Fraud prevention sections">
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'overview'" [class.active]="tab === 'overview'" (click)="go('overview')">Overview</button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'rules'" [class.active]="tab === 'rules'" (click)="go('rules')">Rules</button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'review'" [class.active]="tab === 'review'" (click)="go('review')">
                            Review queue<span class="tab-count" *ngIf="pendingCount">{{ pendingCount }}</span>
                        </button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'lists'" [class.active]="tab === 'lists'" (click)="go('lists')">Lists</button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'simulate'" [class.active]="tab === 'simulate'" (click)="go('simulate')">Simulate</button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'lookup'" [class.active]="tab === 'lookup'" (click)="go('lookup')">Lookup</button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'activity'" [class.active]="tab === 'activity'" (click)="go('activity')">Activity</button>
                        <button class="tab" role="tab" [attr.aria-selected]="tab === 'settings'" [class.active]="tab === 'settings'" (click)="go('settings')">Settings</button>
                    </div>
                </div>
            </div>
        </vdr-page-block>

        <!-- ============================================================ OVERVIEW -->
        <ng-container *ngIf="!loading && current && tab === 'overview'">
            <vdr-page-block>
                <div class="kpi-row">
                    <div class="kpi">
                        <div class="kpi-label">Orders assessed</div>
                        <div class="kpi-num">{{ stats?.totals?.assessed || 0 }}</div>
                        <div class="kpi-sub">last {{ statsDays }} days</div>
                    </div>
                    <div class="kpi">
                        <div class="kpi-label">Flagged risky</div>
                        <div class="kpi-num">{{ stats?.totals?.flagged || 0 }}</div>
                        <div class="kpi-sub">scored ≥ review threshold</div>
                    </div>
                    <div class="kpi" [class.kpi-alert]="pendingCount > 0">
                        <div class="kpi-label">Awaiting review</div>
                        <div class="kpi-num">{{ pendingCount }}</div>
                        <div class="kpi-sub"><a href="javascript:void(0)" (click)="go('review')">open the queue →</a></div>
                    </div>
                    <div class="kpi">
                        <div class="kpi-label">Failed payments</div>
                        <div class="kpi-num">{{ stats?.failedPayments24 || 0 }}</div>
                        <div class="kpi-sub">last 24 hours</div>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Daily assessments <small>last {{ statsDays }} days</small></h3>
                        <div class="chart-legend">
                            <span class="leg"><span class="leg-dot leg-assessed"></span> Assessed</span>
                            <span class="leg"><span class="leg-dot leg-flagged"></span> Flagged</span>
                        </div>
                        <div class="bar-chart" *ngIf="stats?.daily?.length; else noChart" role="img"
                             [attr.aria-label]="'Daily order assessments over the last ' + statsDays + ' days'">
                            <div class="bar-col" *ngFor="let d of stats.daily"
                                 [title]="d.day + ': ' + d.assessed + ' assessed, ' + d.flagged + ' flagged'">
                                <div class="bar-stack">
                                    <div class="bar bar-assessed" [style.height.%]="barPct(d.assessed)"></div>
                                    <div class="bar bar-flagged" [style.height.%]="barPct(d.flagged)"></div>
                                </div>
                                <div class="bar-label">{{ d.day | date: 'd MMM' }}</div>
                            </div>
                        </div>
                        <ng-template #noChart><p class="hint">No assessments yet — the chart fills in as orders arrive.</p></ng-template>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block>
                <div class="two-col">
                    <div class="card">
                        <div class="card-block">
                            <h3 class="step-title">Most active IPs <small>24h</small></h3>
                            <table class="table" *ngIf="stats?.topIps?.length; else noIps">
                                <thead><tr><th>IP</th><th class="num-col">Orders</th><th></th></tr></thead>
                                <tbody>
                                    <tr *ngFor="let r of stats.topIps">
                                        <td class="mono">{{ r.ip }}</td>
                                        <td class="num-col">{{ r.n }}</td>
                                        <td class="num-col"><button class="gbtn gbtn-ghost gbtn-sm" (click)="quickBlockIp(r.ip)">Block</button></td>
                                    </tr>
                                </tbody>
                            </table>
                            <ng-template #noIps><p class="hint">No orders in the last 24 hours.</p></ng-template>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-block">
                            <h3 class="step-title">Assessments by risk level <small>last {{ statsDays }} days</small></h3>
                            <div class="level-rows" *ngIf="stats?.byLevel?.length; else noLevels">
                                <div class="level-row" *ngFor="let r of stats.byLevel">
                                    <span class="level-pill" [ngClass]="'lvl-' + r.riskLevel">{{ r.riskLevel }}</span>
                                    <span class="mini-track"><span class="mini-fill" [style.width.%]="levelPct(r.n)"></span></span>
                                    <span class="level-n">{{ r.n }}</span>
                                </div>
                            </div>
                            <ng-template #noLevels><p class="hint">Nothing scored yet.</p></ng-template>
                        </div>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ RULES -->
        <ng-container *ngIf="!loading && current && tab === 'rules'">
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Enforcement mode</h3>
                        <div class="mode-grid">
                            <label class="mode-card" [class.active]="current.mode === 'off'">
                                <input type="radio" name="fmode" value="off" [(ngModel)]="current.mode" (ngModelChange)="markDirty()">
                                <div class="mode-title">Off</div>
                                <div class="mode-body">No scoring, no logging. Orders flow untouched.</div>
                            </label>
                            <label class="mode-card" [class.active]="current.mode === 'monitor'">
                                <input type="radio" name="fmode" value="monitor" [(ngModel)]="current.mode" (ngModelChange)="markDirty()">
                                <div class="mode-title">Monitor</div>
                                <div class="mode-body">Score + log every order, flag the risky ones — but never hold anything. The safe way to tune thresholds.</div>
                            </label>
                            <label class="mode-card" [class.active]="current.mode === 'enforce'">
                                <input type="radio" name="fmode" value="enforce" [(ngModel)]="current.mode" (ngModelChange)="markDirty()" [disabled]="meta && !meta.licensed">
                                <div class="mode-title">Enforce <span class="mini-chip" *ngIf="meta && !meta.licensed">licence required</span></div>
                                <div class="mode-body">Risky orders are held in the review queue and licence keys wait for your approval.</div>
                            </label>
                        </div>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Protection level</h3>
                        <p class="hint">One click sets thresholds and velocity limits to a sensible bundle. Fine-tune anything under Advanced — the level shows as Custom once you do.</p>
                        <div class="mode-grid">
                            <label class="mode-card" *ngFor="let p of presets" [class.active]="activePreset() === p.key">
                                <input type="radio" name="preset" [value]="p.key" [checked]="activePreset() === p.key" (change)="applyPreset(p.key)">
                                <div class="mode-title">{{ p.label }} <span class="mini-chip" *ngIf="p.key === 'balanced'">recommended</span></div>
                                <div class="mode-body">{{ p.description }}</div>
                            </label>
                        </div>
                        <p class="hint" *ngIf="activePreset() === 'custom'" style="margin-top:8px">Currently: <strong>Custom</strong> — your own values (see Advanced below).</p>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <button class="gbtn gbtn-outline" (click)="advancedOpen = !advancedOpen" [attr.aria-expanded]="advancedOpen">
                            {{ advancedOpen ? '▾ Hide advanced settings' : '▸ Advanced settings' }}
                        </button>
                        <p class="hint inline" style="margin-left:10px">thresholds, velocity limits, signals, review workflow</p>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block *ngIf="advancedOpen">
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Risk thresholds</h3>
                        <p class="hint">Each fired signal adds points (see the exact contributions in Simulate). Totals at or above these values change what happens to the order.</p>
                        <div class="form-grid">
                            <div class="form-row">
                                <label>Hold for review at <small>(score 0–100)</small></label>
                                <input class="form-input" type="number" min="1" max="100" [(ngModel)]="current.reviewThreshold" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Treat as blocked at <small>(score 0–100)</small></label>
                                <input class="form-input" type="number" min="1" max="100" [(ngModel)]="current.blockThreshold" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label class="check-label">
                                    <input type="checkbox" [(ngModel)]="current.holdFulfilment" (ngModelChange)="markDirty()">
                                    Hold licence-key fulfilment while a case is pending
                                </label>
                            </div>
                            <div class="form-row">
                                <label>Auto-approve unreviewed cases after <small>(hours, 0 = never)</small></label>
                                <input class="form-input" type="number" min="0" [(ngModel)]="current.autoApproveAfterHours" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Tell the customer their order is held</label>
                                <select class="form-select" style="width:100%" [(ngModel)]="current.notifyCustomerOnHold" (ngModelChange)="markDirty()">
                                    <option value="never">Never — review silently</option>
                                    <option value="block">Only blocked-level holds (default)</option>
                                    <option value="always">Every held order</option>
                                </select>
                            </div>
                            <div class="form-row">
                                <label>Promised review turnaround <small>(hours — used as {{ '{' }}{{ '{' }}reviewHours{{ '}' }}{{ '}' }} in messages)</small></label>
                                <input class="form-input" type="number" min="1" [(ngModel)]="current.reviewHours" (ngModelChange)="markDirty()">
                            </div>
                        </div>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block *ngIf="advancedOpen">
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Velocity limits</h3>
                        <div class="form-grid">
                            <div class="form-row">
                                <label>Orders per IP per hour</label>
                                <input class="form-input" type="number" min="1" [(ngModel)]="current.maxOrdersPerIpPerHour" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Orders per IP per day</label>
                                <input class="form-input" type="number" min="1" [(ngModel)]="current.maxOrdersPerIpPerDay" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Orders per email per day</label>
                                <input class="form-input" type="number" min="1" [(ngModel)]="current.maxOrdersPerEmailPerDay" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Max daily value per email <small>(£)</small></label>
                                <input class="form-input" type="number" min="0" [ngModel]="current.maxDailyValuePerEmailPence / 100" (ngModelChange)="current.maxDailyValuePerEmailPence = $event * 100; markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Max order value <small>(£)</small></label>
                                <input class="form-input" type="number" min="0" [ngModel]="current.maxOrderValuePence / 100" (ngModelChange)="current.maxOrderValuePence = $event * 100; markDirty()">
                            </div>
                            <div class="form-row">
                                <label>First-order caution above <small>(£)</small></label>
                                <input class="form-input" type="number" min="0" [ngModel]="current.requireEmailVerificationAbovePence / 100" (ngModelChange)="current.requireEmailVerificationAbovePence = $event * 100; markDirty()">
                            </div>
                        </div>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block *ngIf="advancedOpen">
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Signals</h3>
                        <div class="form-grid">
                            <label class="check-label"><input type="checkbox" [(ngModel)]="current.blockDisposableEmails" (ngModelChange)="markDirty()"> Penalise disposable email domains</label>
                            <label class="check-label"><input type="checkbox" [(ngModel)]="current.enforce3dSecure" (ngModelChange)="markDirty()"> Require 3-D Secure on card payments</label>
                            <label class="check-label"><input type="checkbox" [(ngModel)]="current.blockHighRiskCountries" (ngModelChange)="markDirty()"> Penalise high-risk countries</label>
                        </div>
                        <div class="form-row" *ngIf="current.blockHighRiskCountries" style="margin-top:10px">
                            <label>High-risk country codes <small>(comma-separated ISO codes)</small></label>
                            <input class="form-input" [(ngModel)]="current.highRiskCountries" (ngModelChange)="markDirty()" placeholder="NG, PK, VN">
                        </div>
                        <div class="form-grid" style="margin-top:14px">
                            <div class="form-row">
                                <label>Failed payments per IP per hour</label>
                                <input class="form-input" type="number" min="1" [(ngModel)]="current.maxFailedPaymentsPerIpPerHour" (ngModelChange)="markDirty()">
                            </div>
                            <div class="form-row">
                                <label>Cooldown after failed payment <small>(minutes)</small></label>
                                <input class="form-input" type="number" min="0" [(ngModel)]="current.cooldownMinutesAfterFailedPayment" (ngModelChange)="markDirty()">
                            </div>
                        </div>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ REVIEW QUEUE -->
        <ng-container *ngIf="!loading && current && tab === 'review'">
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <div class="row-between">
                            <h3 class="step-title" style="margin:0">Review queue</h3>
                            <span class="mode-seg">
                                <button *ngFor="let f of caseFilters" class="seg" [class.active]="caseFilter === f" (click)="caseFilter = f; loadCases()">{{ f || 'all' }}</button>
                            </span>
                        </div>
                        <p class="hint">Approve releases held licence keys; reject cancels the order. The <em>email customer</em> tick controls whether they hear about it — untick to resolve silently. <em>Blocklist</em> (with reject) quietly bans the email + IP so a fraudster learns nothing and still can't come back.</p>

                        <table class="table" *ngIf="cases.length; else noCases">
                            <thead><tr><th>Order</th><th>Customer</th><th>Score</th><th>Signals</th><th>Age</th><th>Status</th><th></th></tr></thead>
                            <tbody>
                                <tr *ngFor="let c of cases">
                                    <td><strong>{{ c.orderCode || c.liveOrderCode || ('#' + c.orderId) }}</strong><div class="hint" *ngIf="c.subTotalWithTax">£{{ (c.subTotalWithTax / 100).toFixed(2) }}</div></td>
                                    <td>{{ c.email }}<div class="hint mono" *ngIf="c.ip">{{ c.ip }}</div></td>
                                    <td><span class="score-pill" [ngClass]="scoreClass(c.riskScore)">{{ c.riskScore }}</span></td>
                                    <td class="signals-cell">
                                        <span class="mini-chip" *ngFor="let s of parseSignals(c.signals)" [title]="s.detail">{{ s.label }}</span>
                                        <span class="hint" *ngIf="!parseSignals(c.signals).length">{{ c.reasons }}</span>
                                    </td>
                                    <td class="hint">{{ c.createdAt | date: 'd MMM HH:mm' }}</td>
                                    <td><span class="level-pill" [ngClass]="'lvl-' + (c.status === 'pending' ? c.riskLevel : c.status)">{{ c.status }}</span></td>
                                    <td class="num-col case-actions">
                                        <ng-container *ngIf="c.status === 'pending'">
                                            <input class="form-input notes-input" placeholder="notes…" [(ngModel)]="caseNotes[c.id]">
                                            <span class="case-opts">
                                                <label class="check-label check-sm" title="Send the customer your approved / rejected message. Untick to resolve silently.">
                                                    <input type="checkbox" [(ngModel)]="caseNotifyOverride[c.id]"> email customer
                                                </label>
                                                <label class="check-label check-sm" title="On reject: silently blocklist this email + IP so future attempts stop at the door. Defaults to your global setting.">
                                                    <input type="checkbox" [(ngModel)]="caseBlocklist[c.id]"> blocklist
                                                </label>
                                            </span>
                                            <button class="gbtn gbtn-primary gbtn-sm" (click)="resolveCase(c, 'approve')" [disabled]="busyCase === c.id">Approve</button>
                                            <button class="gbtn gbtn-ghost gbtn-danger gbtn-sm" (click)="resolveCase(c, 'reject')" [disabled]="busyCase === c.id">Reject</button>
                                        </ng-container>
                                        <span class="hint" *ngIf="c.status !== 'pending' && c.reviewNotes">{{ c.reviewNotes }}</span>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                        <ng-template #noCases><p class="hint">No {{ caseFilter || '' }} cases. When enforce mode holds an order it appears here.</p></ng-template>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ LISTS -->
        <ng-container *ngIf="!loading && current && tab === 'lists'">
            <vdr-page-block>
                <div class="two-col">
                    <div class="card">
                        <div class="card-block">
                            <h3 class="step-title">Allowlist <small>(always trusted)</small></h3>
                            <p class="hint">Trusted identities bypass every check — your own test accounts, key B2B customers, office IPs.</p>
                            <div class="picker">
                                <select class="form-select" style="min-width:130px" [(ngModel)]="newWl.type">
                                    <option value="email">email</option>
                                    <option value="email_domain">email domain</option>
                                    <option value="ip">IP</option>
                                </select>
                                <input class="form-input" placeholder="value" [(ngModel)]="newWl.value" (keyup.enter)="addEntry('whitelist')">
                                <input class="form-input" placeholder="note (optional)" [(ngModel)]="newWl.note">
                                <button class="gbtn gbtn-outline gbtn-sm" (click)="addEntry('whitelist')" [disabled]="!newWl.value">+ Add</button>
                            </div>
                            <table class="table" *ngIf="wl.length">
                                <thead><tr><th>Type</th><th>Value</th><th>Note</th><th></th></tr></thead>
                                <tbody>
                                    <tr *ngFor="let e of wl">
                                        <td>{{ e.type }}</td><td class="mono">{{ e.value }}</td><td class="hint">{{ e.note }}</td>
                                        <td class="num-col"><button class="chip-x" (click)="removeEntry('whitelist', e.id)" [attr.aria-label]="'Remove ' + e.value">×</button></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-block">
                            <h3 class="step-title">Manual blocklist</h3>
                            <p class="hint">Your own bans, on top of the threat feeds below.</p>
                            <div class="picker">
                                <select class="form-select" style="min-width:130px" [(ngModel)]="newBl.type">
                                    <option value="email">email</option>
                                    <option value="email_domain">email domain</option>
                                    <option value="ip">IP</option>
                                    <option value="ip_range">IP range (CIDR)</option>
                                </select>
                                <input class="form-input" placeholder="value" [(ngModel)]="newBl.value" (keyup.enter)="addEntry('blocklist')">
                                <input class="form-input" placeholder="note (optional)" [(ngModel)]="newBl.note">
                                <button class="gbtn gbtn-outline gbtn-sm" (click)="addEntry('blocklist')" [disabled]="!newBl.value">+ Add</button>
                            </div>
                            <table class="table" *ngIf="bl.length">
                                <thead><tr><th>Type</th><th>Value</th><th>Note</th><th></th></tr></thead>
                                <tbody>
                                    <tr *ngFor="let e of bl">
                                        <td>{{ e.listType }}</td><td class="mono">{{ e.value }}</td><td class="hint">{{ e.note }}</td>
                                        <td class="num-col"><button class="chip-x" (click)="removeEntry('blocklist', e.id)" [attr.aria-label]="'Remove ' + e.value">×</button></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <div class="row-between">
                            <h3 class="step-title" style="margin:0">Threat feeds</h3>
                            <button class="gbtn gbtn-primary gbtn-sm" (click)="syncAll()" [disabled]="syncBusy || (meta && !meta.licensed)">
                                {{ syncBusy ? 'Syncing…' : 'Sync all now' }}
                            </button>
                        </div>
                        <p class="hint">Public reputation lists, refreshed daily at 03:00. <span *ngIf="meta && !meta.licensed" class="warn-inline">Feed sync requires a licence — existing synced entries keep working.</span></p>
                        <table class="table">
                            <thead><tr><th>Feed</th><th>Type</th><th class="num-col">Entries</th><th>Last synced</th><th></th></tr></thead>
                            <tbody>
                                <tr *ngFor="let s of sources">
                                    <td><strong>{{ s.name }}</strong><div class="hint">{{ s.description }}</div></td>
                                    <td>{{ s.type }}</td>
                                    <td class="num-col">{{ feedCount(s.key) }}</td>
                                    <td class="hint">{{ feedUpdated(s.key) ? (feedUpdated(s.key) | date: 'd MMM HH:mm') : 'never' }}</td>
                                    <td class="num-col"><button class="gbtn gbtn-outline gbtn-sm" (click)="syncOne(s.key)" [disabled]="syncBusy || (meta && !meta.licensed)">Sync</button></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </vdr-page-block>

            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Custom feeds <small>your own threat-list URLs</small></h3>
                        <p class="hint">Add any public line-based blocklist (one entry per line; <code class="mono">#</code> comments ignored). Synced nightly with the built-ins and matched exactly like them — CIDR ranges included. <span *ngIf="meta && !meta.licensed" class="warn-inline">Custom feeds require a licence.</span></p>
                        <div class="picker">
                            <input class="form-input" style="min-width:150px" placeholder="Name (e.g. IPsum)" [(ngModel)]="newFeed.name">
                            <input class="form-input" style="flex:1;min-width:220px" placeholder="https://…/list.txt" [(ngModel)]="newFeed.url">
                            <select class="form-select" style="min-width:130px" [(ngModel)]="newFeed.listType">
                                <option value="ip">IP</option>
                                <option value="ip_range">IP range (CIDR)</option>
                                <option value="email_domain">email domain</option>
                                <option value="email">email</option>
                            </select>
                            <button class="gbtn gbtn-outline gbtn-sm" (click)="addFeed()" [disabled]="!newFeed.name || !newFeed.url || (meta && !meta.licensed)">+ Add feed</button>
                        </div>
                        <table class="table" *ngIf="customFeeds.length">
                            <thead><tr><th>Feed</th><th>Type</th><th class="num-col">Entries</th><th>Last synced</th><th>On</th><th></th></tr></thead>
                            <tbody>
                                <tr *ngFor="let f of customFeeds">
                                    <td><strong>{{ f.name }}</strong><div class="hint mono">{{ f.url }}</div>
                                        <div class="hint" style="color:var(--gb-danger-ink)" *ngIf="f.lastError">⚠ {{ f.lastError }}</div></td>
                                    <td>{{ f.listType }}</td>
                                    <td class="num-col">{{ f.lastCount != null ? f.lastCount : '—' }}</td>
                                    <td class="hint">{{ f.lastSyncedAt ? (f.lastSyncedAt | date: 'd MMM HH:mm') : 'never' }}</td>
                                    <td><label class="check-label"><input type="checkbox" [checked]="!!f.enabled" (change)="toggleFeed(f)"></label></td>
                                    <td class="num-col case-actions">
                                        <button class="gbtn gbtn-outline gbtn-sm" (click)="syncFeed(f)" [disabled]="syncBusy || (meta && !meta.licensed)">Sync</button>
                                        <button class="chip-x" (click)="removeFeed(f)" [attr.aria-label]="'Remove ' + f.name">×</button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                        <p class="hint" *ngIf="!customFeeds.length">No custom feeds yet. Popular options: IPsum, blocklist.de, FireHOL Level 2–4, Emerging Threats.</p>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ SIMULATE -->
        <ng-container *ngIf="!loading && current && tab === 'simulate'">
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Simulate an order</h3>
                        <p class="hint">Runs the full assessment against live data (velocity counts real orders) without logging anything or holding anything.</p>
                        <div class="sim-grid">
                            <div><label>Email</label><input class="form-input" [(ngModel)]="sim.email" placeholder="test@example.com"></div>
                            <div><label>IP address</label><input class="form-input mono" [(ngModel)]="sim.ip" placeholder="203.0.113.42"></div>
                            <div><label>Order value <small>(£)</small></label><input class="form-input" type="number" min="0" [(ngModel)]="sim.valueGbp"></div>
                            <div><label>Country <small>(optional)</small></label><input class="form-input" [(ngModel)]="sim.country" placeholder="GB" maxlength="2" style="text-transform:uppercase"></div>
                        </div>
                        <label class="check-label" style="margin-bottom:12px"><input type="checkbox" [(ngModel)]="sim.newCustomer"> Treat as first-time customer</label>
                        <div>
                            <button class="gbtn gbtn-primary" (click)="runSim()" [disabled]="simBusy">{{ simBusy ? 'Running…' : 'Run assessment' }}</button>
                        </div>

                        <div class="sim-result" *ngIf="simResult">
                            <div class="sim-banner" [ngClass]="simResult.action === 'allow' ? 'allow' : simResult.action === 'flag' ? 'flag' : 'deny'">
                                <strong>Score {{ simResult.score }}/100 — {{ simResult.level }}</strong>
                                <span *ngIf="simResult.allowlisted"> (allowlisted — every check bypassed)</span>
                                <span *ngIf="!simResult.allowlisted"> → {{ actionSentence(simResult.action) }}</span>
                            </div>
                            <table class="table" *ngIf="simResult.signals?.length">
                                <thead><tr><th>Signal</th><th class="num-col">Points</th><th>Detail</th></tr></thead>
                                <tbody>
                                    <tr *ngFor="let s of simResult.signals">
                                        <td><strong>{{ s.label }}</strong></td>
                                        <td class="num-col">+{{ s.points }}</td>
                                        <td class="hint">{{ s.detail }}</td>
                                    </tr>
                                </tbody>
                            </table>
                            <p class="hint" *ngIf="!simResult.signals?.length && !simResult.allowlisted">No signals fired — this order looks clean.</p>
                        </div>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ LOOKUP -->
        <ng-container *ngIf="!loading && current && tab === 'lookup'">
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Customer lookup</h3>
                        <p class="hint">Full dossier for any email — order history, spend, failed payments, prior cases and list status. Plus-addressed variants are folded into one identity.</p>
                        <div class="picker">
                            <input class="form-input" style="min-width:280px" placeholder="customer@example.com" [(ngModel)]="lookupEmail" (keyup.enter)="runLookup()">
                            <button class="gbtn gbtn-primary" (click)="runLookup()" [disabled]="lookupBusy || !lookupEmail">{{ lookupBusy ? 'Looking…' : 'Look up' }}</button>
                        </div>

                        <div *ngIf="profile">
                            <div class="sim-banner" [ngClass]="profile.onBlocklist ? 'deny' : profile.onAllowlist ? 'allow' : 'flag'" style="margin-top:8px">
                                <strong>{{ profile.email }}</strong>
                                <span *ngIf="profile.canonical !== profile.email"> (canonical: {{ profile.canonical }})</span>
                                — {{ profile.onBlocklist ? '🚫 on the blocklist' : profile.onAllowlist ? '✅ on the allowlist' : 'not on any list' }}<span *ngIf="profile.usedPlusAddressing"> · uses plus-addressing</span>
                            </div>
                            <div class="kpi-row" style="margin:14px 0">
                                <div class="kpi"><div class="kpi-label">Orders</div><div class="kpi-num">{{ profile.totals?.orders || 0 }}</div><div class="kpi-sub">{{ profile.totals?.settled || 0 }} settled · {{ profile.totals?.cancelled || 0 }} cancelled</div></div>
                                <div class="kpi"><div class="kpi-label">Lifetime value</div><div class="kpi-num">£{{ ((profile.totals?.lifetimeValue || 0) / 100) | number:'1.0-0' }}</div><div class="kpi-sub" *ngIf="profile.totals?.firstOrder">since {{ profile.totals.firstOrder | date:'MMM y' }}</div></div>
                                <div class="kpi" [class.kpi-alert]="profile.failedPayments > 0"><div class="kpi-label">Failed payments</div><div class="kpi-num">{{ profile.failedPayments }}</div><div class="kpi-sub">all time</div></div>
                                <div class="kpi" [class.kpi-alert]="profile.cases?.length > 0"><div class="kpi-label">Fraud cases</div><div class="kpi-num">{{ profile.cases?.length || 0 }}</div><div class="kpi-sub">most recent 10</div></div>
                            </div>
                            <div class="picker" style="margin-bottom:16px">
                                <button class="gbtn gbtn-outline gbtn-sm" (click)="lookupListAction('whitelist')" [disabled]="profile.onAllowlist">Add to allowlist</button>
                                <button class="gbtn gbtn-ghost gbtn-danger gbtn-sm" (click)="lookupListAction('blocklist')" [disabled]="profile.onBlocklist">Add to blocklist</button>
                            </div>
                            <h4 class="step-title" style="font-size:13px">Recent orders</h4>
                            <table class="table" *ngIf="profile.recentOrders?.length; else noProfOrders">
                                <thead><tr><th>Order</th><th>State</th><th class="num-col">Value</th><th>IP</th><th>Placed</th></tr></thead>
                                <tbody>
                                    <tr *ngFor="let o of profile.recentOrders">
                                        <td><strong>{{ o.code }}</strong></td><td>{{ o.state }}</td>
                                        <td class="num-col">£{{ (o.subTotalWithTax / 100).toFixed(2) }}</td>
                                        <td class="mono hint">{{ o.ip || '—' }}</td>
                                        <td class="hint">{{ o.orderPlacedAt | date:'d MMM y HH:mm' }}</td>
                                    </tr>
                                </tbody>
                            </table>
                            <ng-template #noProfOrders><p class="hint">No orders found for this identity.</p></ng-template>
                            <h4 class="step-title" style="font-size:13px;margin-top:16px" *ngIf="profile.log?.length">Assessment history</h4>
                            <table class="table" *ngIf="profile.log?.length">
                                <thead><tr><th>When</th><th>Order</th><th class="num-col">Score</th><th>Level</th><th>Action</th></tr></thead>
                                <tbody>
                                    <tr *ngFor="let r of profile.log">
                                        <td class="hint">{{ r.createdAt | date:'d MMM HH:mm' }}</td>
                                        <td>{{ r.orderCode || '—' }}</td>
                                        <td class="num-col"><span class="score-pill" [ngClass]="scoreClass(r.riskScore)">{{ r.riskScore }}</span></td>
                                        <td><span class="level-pill" [ngClass]="'lvl-' + r.riskLevel">{{ r.riskLevel }}</span></td>
                                        <td>{{ r.action }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ ACTIVITY -->
        <ng-container *ngIf="!loading && current && tab === 'activity'">
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <div class="row-between">
                            <h3 class="step-title" style="margin:0">Audit log</h3>
                            <span class="picker">
                                <select class="form-select" [(ngModel)]="logLevel" (ngModelChange)="loadLog()">
                                    <option value="">all levels</option>
                                    <option value="low">low</option><option value="medium">medium</option>
                                    <option value="review">review</option><option value="blocked">blocked</option>
                                </select>
                                <select class="form-select" [(ngModel)]="logAction" (ngModelChange)="loadLog()">
                                    <option value="">all actions</option>
                                    <option value="allow">allow</option><option value="flag">flag</option>
                                    <option value="review">review</option><option value="block">block</option>
                                    <option value="approved">approved</option><option value="rejected">rejected</option>
                                </select>
                                <button class="gbtn gbtn-outline gbtn-sm" (click)="exportCsv()" [disabled]="!logRows.length">Export CSV</button>
                            </span>
                        </div>
                        <table class="table" *ngIf="logRows.length; else noLog">
                            <thead><tr><th>When</th><th>Order</th><th>Identity</th><th class="num-col">Score</th><th>Level</th><th>Action</th><th>Reasons</th></tr></thead>
                            <tbody>
                                <tr *ngFor="let r of logRows">
                                    <td class="hint">{{ r.createdAt | date: 'd MMM HH:mm' }}</td>
                                    <td><strong>{{ r.orderCode || (r.orderId ? '#' + r.orderId : '—') }}</strong></td>
                                    <td>{{ r.email || '—' }}<div class="hint mono" *ngIf="r.ip">{{ r.ip }}</div></td>
                                    <td class="num-col"><span class="score-pill" [ngClass]="scoreClass(r.riskScore)">{{ r.riskScore }}</span></td>
                                    <td><span class="level-pill" [ngClass]="'lvl-' + r.riskLevel">{{ r.riskLevel }}</span></td>
                                    <td>{{ r.action }}</td>
                                    <td class="hint reasons-cell">{{ r.reasons || '—' }}</td>
                                </tr>
                            </tbody>
                        </table>
                        <ng-template #noLog><p class="hint">Nothing logged yet{{ current.mode === 'off' ? ' — the channel is off' : '' }}.</p></ng-template>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ SETTINGS -->
        <ng-container *ngIf="!loading && current && tab === 'settings'">
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Notifications</h3>
                        <p class="hint">Where alerts go when an order is held, approved or rejected. Connect as many channels as you like — every event pings all of them.</p>
                        <div class="integrations" *ngIf="notif">
                            <div class="integ-row" *ngFor="let ch of integrations">
                                <button class="integ-head" (click)="integOpen = integOpen === ch.key ? '' : ch.key" [attr.aria-expanded]="integOpen === ch.key">
                                    <span class="integ-icon" aria-hidden="true">{{ ch.icon }}</span>
                                    <span class="integ-name">{{ ch.name }}</span>
                                    <span class="integ-desc">{{ ch.description }}</span>
                                    <span class="status-dot" [class.on]="isConfigured(ch.key)" aria-hidden="true"></span>
                                    <span class="integ-state">{{ isConfigured(ch.key) ? 'Connected' : 'Off' }}</span>
                                    <span class="integ-chev" aria-hidden="true">{{ integOpen === ch.key ? '▾' : '▸' }}</span>
                                </button>
                                <div class="integ-body" *ngIf="integOpen === ch.key">
                                    <ng-container [ngSwitch]="ch.key">
                                        <ng-container *ngSwitchCase="'email'">
                                            <p class="hint">SMTP: <strong>{{ notif.smtpConfigured ? '✓ configured on the server' : '✗ not configured — set SMTP_SERVER / SMTP_USER env vars' }}</strong></p>
                                            <div class="form-row">
                                                <label>Send alerts to</label>
                                                <input class="form-input" [(ngModel)]="notif.adminEmail" (ngModelChange)="notifDirty = true" placeholder="you@company.com">
                                            </div>
                                            <label class="check-label"><input type="checkbox" [(ngModel)]="notif.notifyOnBlocked" (ngModelChange)="notifDirty = true"> Alert me on blocked-level holds</label>
                                            <label class="check-label"><input type="checkbox" [(ngModel)]="notif.notifyOnHighRisk" (ngModelChange)="notifDirty = true"> Alert me on review-level holds</label>
                                            <label class="check-label"><input type="checkbox" [(ngModel)]="notif.notifyOnApproval" (ngModelChange)="notifDirty = true"> Email the customer when I approve their order</label>
                                            <label class="check-label"><input type="checkbox" [(ngModel)]="notif.notifyOnRejection" (ngModelChange)="notifDirty = true"> Email the customer when I reject their order</label>
                                            <label class="check-label"><input type="checkbox" [(ngModel)]="notif.blocklistOnReject" (ngModelChange)="notifDirty = true"> Silently blocklist the email + IP whenever I reject (no tip-off)</label>
                                        </ng-container>
                                        <div class="form-row" *ngSwitchCase="'slack'">
                                            <label>Incoming webhook URL</label>
                                            <input class="form-input" [(ngModel)]="notif.slackWebhookUrl" (ngModelChange)="notifDirty = true" placeholder="https://hooks.slack.com/services/…">
                                        </div>
                                        <div class="form-row" *ngSwitchCase="'discord'">
                                            <label>Channel webhook URL</label>
                                            <input class="form-input" [(ngModel)]="notif.discordWebhookUrl" (ngModelChange)="notifDirty = true" placeholder="https://discord.com/api/webhooks/…">
                                        </div>
                                        <div class="form-row" *ngSwitchCase="'teams'">
                                            <label>Incoming webhook URL</label>
                                            <input class="form-input" [(ngModel)]="notif.teamsWebhookUrl" (ngModelChange)="notifDirty = true" placeholder="https://….webhook.office.com/…">
                                        </div>
                                        <ng-container *ngSwitchCase="'telegram'">
                                            <div class="form-row">
                                                <label>Bot token <small>(from &#64;BotFather)</small></label>
                                                <input class="form-input mono" [(ngModel)]="notif.telegramBotToken" (ngModelChange)="notifDirty = true" placeholder="123456:ABC-…">
                                            </div>
                                            <div class="form-row">
                                                <label>Chat ID</label>
                                                <input class="form-input mono" [(ngModel)]="notif.telegramChatId" (ngModelChange)="notifDirty = true" placeholder="-1001234567890">
                                            </div>
                                        </ng-container>
                                        <ng-container *ngSwitchCase="'webhook'">
                                            <div class="form-row">
                                                <label>URL <small>(receives a JSON POST per event)</small></label>
                                                <input class="form-input" [(ngModel)]="notif.genericWebhookUrl" (ngModelChange)="notifDirty = true" placeholder="https://your-system/hooks/fraud">
                                            </div>
                                            <div class="form-row">
                                                <label>Signing secret <small>(optional — HMAC-SHA256 in X-Hulo-Signature)</small></label>
                                                <input class="form-input mono" [(ngModel)]="notif.genericWebhookSecret" (ngModelChange)="notifDirty = true" placeholder="optional">
                                            </div>
                                        </ng-container>
                                    </ng-container>
                                </div>
                            </div>
                        </div>
                        <div style="margin-top:14px">
                            <button class="gbtn gbtn-primary gbtn-sm" (click)="saveNotif()" [disabled]="!notifDirty">Save notification settings</button>
                        </div>
                    </div>
                </div>
            </vdr-page-block>
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">Customer messages <small>({{ current.channelCode }})</small></h3>
                        <p class="hint">What gated customers hear, in your voice. Build it visually, drag in variables, or switch to HTML. Variables: <code class="mono">{{ '{' }}{{ '{' }}orderCode{{ '}' }}{{ '}' }}</code> <code class="mono">{{ '{' }}{{ '{' }}firstName{{ '}' }}{{ '}' }}</code> <code class="mono">{{ '{' }}{{ '{' }}supportEmail{{ '}' }}{{ '}' }}</code> <code class="mono">{{ '{' }}{{ '{' }}reviewHours{{ '}' }}{{ '}' }}</code></p>
                        <div class="tpl-list" *ngIf="templates">
                            <div class="tpl-list-row" *ngFor="let k of templateKinds">
                                <input type="checkbox" [(ngModel)]="tplSelected[k.key]" [attr.aria-label]="'Select ' + k.label + ' template'">
                                <button class="tpl-pick" [class.active]="tplKind === k.key" (click)="selectKind(k.key)">
                                    <span>{{ k.label }}</span>
                                    <span class="mini-chip" *ngIf="templates[k.key]?.isDefault">default</span>
                                    <span class="mini-chip custom" *ngIf="!templates[k.key]?.isDefault">customised</span>
                                </button>
                            </div>
                        </div>
                        <div class="picker" style="margin:0 0 14px">
                            <button class="gbtn gbtn-ghost gbtn-sm" (click)="resetSelected()" [disabled]="!anyTplSelected">Reset selected to default</button>
                            <button class="gbtn gbtn-ghost gbtn-sm" (click)="resetAllTemplates()">Reset all to default</button>
                        </div>
                        <div *ngIf="templates && templates[tplKind]">
                            <div class="form-row">
                                <label>Subject <span class="mini-chip" *ngIf="templates[tplKind].isDefault">default</span></label>
                                <input class="form-input" [(ngModel)]="templates[tplKind].subject" (ngModelChange)="tplDirty = true" (focus)="lastFocus='subject'" #subjectInput>
                            </div>
                            <div class="rte">
                                <div class="rte-head">
                                    <div class="rte-toolbar" *ngIf="!htmlMode">
                                        <button type="button" class="rte-btn" title="Bold" (click)="exec('bold')"><b>B</b></button>
                                        <button type="button" class="rte-btn" title="Italic" (click)="exec('italic')"><i>i</i></button>
                                        <button type="button" class="rte-btn" title="Underline" (click)="exec('underline')"><u>U</u></button>
                                        <button type="button" class="rte-btn" title="Strikethrough" (click)="exec('strikeThrough')"><s>S</s></button>
                                        <span class="rte-sep"></span>
                                        <select class="rte-select" title="Text style" (change)="setBlock($any($event.target).value); $any($event.target).selectedIndex=0">
                                            <option value="">Style</option><option value="p">Normal</option><option value="h2">Heading</option><option value="h3">Subheading</option><option value="blockquote">Quote</option>
                                        </select>
                                        <select class="rte-select" title="Text size" (change)="exec('fontSize', $any($event.target).value); $any($event.target).selectedIndex=0">
                                            <option value="">Size</option><option value="1">XS</option><option value="2">S</option><option value="3">M</option><option value="4">L</option><option value="5">XL</option><option value="6">XXL</option>
                                        </select>
                                        <span class="rte-sep"></span>
                                        <label class="rte-btn rte-color" title="Text colour"><span style="text-decoration:underline;text-decoration-color:#e11d48">A</span><input type="color" (change)="exec('foreColor', $any($event.target).value)"></label>
                                        <label class="rte-btn rte-color" title="Highlight"><span style="background:#fde68a;padding:0 2px;color:#111">H</span><input type="color" value="#ffff00" (change)="exec('hiliteColor', $any($event.target).value)"></label>
                                        <span class="rte-sep"></span>
                                        <button type="button" class="rte-btn" title="Bulleted list" (click)="exec('insertUnorderedList')">&#8226;</button>
                                        <button type="button" class="rte-btn" title="Numbered list" (click)="exec('insertOrderedList')">1.</button>
                                        <button type="button" class="rte-btn" title="Indent" (click)="exec('indent')">&#8677;|</button>
                                        <button type="button" class="rte-btn" title="Outdent" (click)="exec('outdent')">|&#8676;</button>
                                        <span class="rte-sep"></span>
                                        <button type="button" class="rte-btn" title="Link" (click)="addLink()">&#128279;</button>
                                        <button type="button" class="rte-btn" title="Insert image by URL" (click)="insertImage()">&#128247;</button>
                                        <button type="button" class="rte-btn" title="Upload / choose from asset library" (click)="pickAsset()">&#128193;</button>
                                        <button type="button" class="rte-btn" title="Insert button" (click)="insertButton()">Btn</button>
                                        <button type="button" class="rte-btn" title="Divider" (click)="exec('insertHorizontalRule')">&#8213;</button>
                                        <span class="rte-sep"></span>
                                        <button type="button" class="rte-btn" title="Align left" (click)="exec('justifyLeft')">&#8676;</button>
                                        <button type="button" class="rte-btn" title="Centre" (click)="exec('justifyCenter')">&#8803;</button>
                                        <button type="button" class="rte-btn" title="Align right" (click)="exec('justifyRight')">&#8677;</button>
                                        <span class="rte-sep"></span>
                                        <button type="button" class="rte-btn" title="Clear formatting" (click)="exec('removeFormat')">T&#215;</button>
                                        <button type="button" class="rte-btn" title="Undo" (click)="exec('undo')">&#8630;</button>
                                        <button type="button" class="rte-btn" title="Redo" (click)="exec('redo')">&#8631;</button>
                                    </div>
                                    <div class="rte-viewtoggle">
                                        <button type="button" class="rte-tab" [class.active]="!htmlMode" (click)="setHtmlMode(false)">Visual</button>
                                        <button type="button" class="rte-tab" [class.active]="htmlMode" (click)="setHtmlMode(true)">HTML</button>
                                    </div>
                                </div>
                                <div class="rte-vars">
                                    <span class="rte-varlabel">Drag or click to insert:</span>
                                    <span class="rte-chip" *ngFor="let v of emailVars" draggable="true" (dragstart)="onVarDrag($event, v.token)" (click)="insertVar(v.token)" [title]="v.token">{{ v.label }}</span>
                                </div>
                                <div class="rte-editor" *ngIf="!htmlMode" #emailEditor contenteditable="true" (input)="onEditorInput()" (blur)="onEditorInput()" (keyup)="saveRange()" (mouseup)="saveRange()" (dragover)="$event.preventDefault()" (drop)="onEditorDrop($event)"></div>
                                <textarea class="rte-source" *ngIf="htmlMode" [(ngModel)]="templates[tplKind].body" (ngModelChange)="tplDirty = true" rows="12" spellcheck="false"></textarea>
                            </div>
                            <div class="picker" style="margin-top:12px">
                                <button class="gbtn gbtn-primary gbtn-sm" (click)="saveTemplate()" [disabled]="!tplDirty">Save message</button>
                                <button class="gbtn gbtn-outline gbtn-sm" (click)="previewTemplate()">Preview</button>
                                <button class="gbtn gbtn-ghost gbtn-sm" (click)="resetTemplate()" [disabled]="templates[tplKind].isDefault">Reset to default</button>
                            </div>
                            <div *ngIf="tplPreview" class="tpl-preview">
                                <div class="tpl-preview-subject">{{ tplPreview.subject }}</div>
                                <div [innerHTML]="tplPreview.html"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </vdr-page-block>
            <vdr-page-block>
                <div class="card">
                    <div class="card-block">
                        <h3 class="step-title">About</h3>
                        <p class="hint" *ngIf="meta">
                            <!--email_off-->{{ meta.name }} v{{ meta.version }}<!--/email_off--> ·
                            Licence: <strong>{{ meta.licensed ? '✓ active' : 'free tier' }}</strong>
                            <span *ngIf="!meta.licensed"> — {{ meta.licenceMessage }}</span>
                        </p>
                        <p class="hint">Audit log retention: 180 days (configurable via plugin options). Threat feeds refresh daily at 03:00.</p>
                    </div>
                </div>
            </vdr-page-block>
        </ng-container>

        <!-- ============================================================ SAVE BAR -->
        <vdr-page-block *ngIf="!loading && current && (tab === 'rules')">
            <div class="save-bar" [class.is-dirty]="dirty">
                <span class="save-msg" *ngIf="dirty"><span class="save-dot" aria-hidden="true"></span> Unsaved changes</span>
                <span class="save-msg quiet" *ngIf="!dirty">All changes saved</span>
                <span class="save-spacer"></span>
                <button class="gbtn gbtn-ghost" (click)="reloadAll()" [disabled]="saving || !dirty">Discard</button>
                <button class="gbtn gbtn-primary" (click)="save()" [disabled]="saving || !dirty">
                    {{ saving ? 'Saving…' : 'Save changes' }}
                </button>
            </div>
        </vdr-page-block>
    `,
    styles: [`
        :host { display: block; color: var(--gb-strong); }

        /* ── Verified theme tokens (HULO admin design system) ─────────
           Same machine-checked token set as geo-block 0.7.4 — every
           text/surface pair >= 4.5:1 and every control boundary >= 3:1
           against the real admin theme values, both themes. */
        :host {
            --gb-surface: var(--color-component-bg-100, #fafafa);
            --gb-surface-2: var(--color-component-bg-200, #f2f3f5);
            --gb-line: var(--color-component-border-200, #d5d8de);
            --gb-line-soft: var(--color-component-border-100, #e8eaee);
            --gb-strong: #3d4147;
            --gb-muted: #5d6470;
            --gb-ui-border: #79818f;
            --gb-amber: #f59e0b;
            --gb-amber-hover: #e18f06;
            --gb-amber-edge: #b45309;
            --gb-amber-ink: #231602;
            --gb-danger-ink: #b91c1c;
            --gb-ok: #10b981; --gb-warn: #f59e0b; --gb-bad: #ef4444; --gb-info: #3b82f6;
            --gb-blue: #2a78d6;
            --gb-tint-ok:   color-mix(in srgb, var(--gb-ok) 10%, var(--gb-surface));
            --gb-tint-warn: color-mix(in srgb, var(--gb-warn) 12%, var(--gb-surface));
            --gb-tint-bad:  color-mix(in srgb, var(--gb-bad) 10%, var(--gb-surface));
            --gb-tint-info: color-mix(in srgb, var(--gb-info) 10%, var(--gb-surface));
            --gb-line-ok:   color-mix(in srgb, var(--gb-ok) 45%, transparent);
            --gb-line-warn: color-mix(in srgb, var(--gb-warn) 50%, transparent);
            --gb-line-bad:  color-mix(in srgb, var(--gb-bad) 45%, transparent);
            --gb-line-info: color-mix(in srgb, var(--gb-info) 45%, transparent);
            --gb-shadow-1: 0 1px 2px rgba(15, 23, 42, 0.06);
        }
        :host-context([data-theme='dark']) {
            --gb-strong: var(--color-text-100, hsl(210, 16%, 93%));
            --gb-muted: hsl(205, 14%, 74%);
            --gb-ui-border: hsl(203, 12%, 50%);
            --gb-amber-edge: #f59e0b;
            --gb-danger-ink: #f87171;
            --gb-blue: #3987e5;
            --gb-shadow-1: 0 1px 2px rgba(0, 0, 0, 0.35);
        }

        /* ── Buttons (self-owned) ─────────────────────────────────── */
        .gbtn {
            display: inline-flex; align-items: center; justify-content: center; gap: 6px;
            min-height: 36px; padding: 0 16px; border-radius: 8px;
            font-size: 13px; font-weight: 600; line-height: 1.2; white-space: nowrap;
            border: 1px solid transparent; background: none; cursor: pointer;
            color: var(--gb-strong); text-decoration: none;
            transition: background 0.12s ease, border-color 0.12s ease, color 0.12s ease, box-shadow 0.12s ease;
        }
        .gbtn:disabled { opacity: 0.45; cursor: not-allowed; }
        .gbtn:focus-visible, .tab:focus-visible, .seg:focus-visible, .chip-x:focus-visible {
            outline: 2px solid var(--gb-amber-edge); outline-offset: 2px;
        }
        .gbtn-sm { min-height: 30px; padding: 0 12px; font-size: 12px; }
        .gbtn-primary { background: var(--gb-amber); border-color: var(--gb-amber-edge); color: var(--gb-amber-ink); box-shadow: var(--gb-shadow-1); }
        .gbtn-primary:hover:not(:disabled) { background: var(--gb-amber-hover); }
        .gbtn-outline { border-color: var(--gb-ui-border); background: var(--gb-surface); }
        .gbtn-outline:hover:not(:disabled) { border-color: var(--gb-amber-edge); background: var(--gb-surface-2); }
        .gbtn-ghost { color: var(--gb-muted); }
        .gbtn-ghost:hover:not(:disabled) { color: var(--gb-strong); background: var(--gb-surface-2); }
        .gbtn-danger { color: var(--gb-danger-ink); }
        .gbtn-danger:hover:not(:disabled) { color: var(--gb-danger-ink); background: var(--gb-tint-bad); }
        .gbtn-hero { color: #e2e8f0; }
        .gbtn-hero:hover:not(:disabled) { color: #ffffff; background: rgba(255, 255, 255, 0.12); }
        .gbtn-hero:focus-visible { outline-color: #f59e0b; }

        /* ── Hero ─────────────────────────────────────────────────── */
        .hulo-hero {
            display: flex; align-items: center; gap: 18px;
            padding: 20px 22px; border-radius: 14px;
            background: linear-gradient(135deg, #0f1419 0%, #1e293b 100%);
            color: #fff;
            box-shadow: 0 1px 3px rgba(15, 23, 42, 0.15), 0 8px 24px rgba(15, 23, 42, 0.08);
        }
        .hulo-hero-logo { flex: 0 0 auto; width: 56px; height: 56px; }
        .hulo-hero-logo svg { width: 100%; height: 100%; display: block; }
        .hulo-hero-text { flex: 1 1 auto; min-width: 0; }
        .hulo-hero-title { color: #fff; font-size: 22px; font-weight: 700; margin: 0; letter-spacing: -0.01em; }
        .hulo-hero-sub { color: #cbd5e1; font-size: 13px; line-height: 1.5; margin: 4px 0 0; max-width: 720px; }
        .hulo-hero-actions { display: flex; gap: 6px; align-items: center; flex: 0 0 auto; }

        /* ── Help drawer ──────────────────────────────────────────── */
        .hulo-help-drawer { background: var(--gb-tint-warn); border: 1px solid var(--gb-line-warn); border-radius: 12px; padding: 20px 22px; color: var(--gb-strong); }
        .hulo-help-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
        .hulo-help-card { background: var(--gb-surface); border-radius: 10px; padding: 16px; border: 1px solid var(--gb-line); }
        .hulo-help-num { width: 24px; height: 24px; border-radius: 999px; background: var(--gb-amber); color: var(--gb-amber-ink); font-weight: 800; font-size: 13px; display: grid; place-items: center; margin-bottom: 8px; }
        .hulo-help-card h4 { margin: 0 0 4px; font-size: 14px; color: var(--gb-strong); }
        .hulo-help-card p { margin: 0; font-size: 13px; line-height: 1.5; color: var(--gb-muted); }
        .hulo-help-links { margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--gb-line-warn); display: flex; gap: 18px; flex-wrap: wrap; font-size: 13px; }
        .hulo-help-links a { color: var(--gb-strong); text-decoration: underline; text-underline-offset: 2px; font-weight: 600; }
        .hulo-help-links a:hover { color: var(--gb-amber-edge); }

        /* ── Cards + layout ───────────────────────────────────────── */
        .card { background: var(--gb-surface); border: 1px solid var(--gb-line); border-radius: 12px; overflow: visible; min-width: 0; box-shadow: var(--gb-shadow-1); }
        .card-block { padding: 18px 20px; }
        .two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }
        .row-between { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 6px; }
        .step-title { font-size: 15px; font-weight: 700; color: var(--gb-strong); margin: 0 0 4px; }
        .step-title small { font-weight: 500; font-size: 12px; color: var(--gb-muted); }
        .hint { font-size: 12px; color: var(--gb-muted); margin: 2px 0 12px; }
        .mono { font-family: ui-monospace, monospace; }
        .warn-inline { color: var(--gb-amber-edge); font-weight: 600; }

        /* ── Top bar ──────────────────────────────────────────────── */
        .top-bar { border-left: 4px solid var(--gb-amber); }
        .chan-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
        .lbl { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--gb-muted); }
        .form-select, .form-input {
            padding: 7px 10px; border-radius: 8px; min-height: 36px;
            border: 1px solid var(--gb-ui-border); background: var(--gb-surface);
            color: var(--gb-strong); font-size: 13px;
        }
        .form-input::placeholder { color: var(--gb-muted); opacity: 0.8; }
        .form-select { min-width: 160px; }
        .form-select:focus, .form-input:focus {
            outline: none; border-color: var(--gb-amber-edge);
            box-shadow: 0 0 0 3px color-mix(in srgb, var(--gb-amber) 30%, transparent);
        }
        .mode-seg { display: inline-flex; border: 1px solid var(--gb-ui-border); border-radius: 999px; overflow: hidden; }
        .seg {
            padding: 7px 14px; min-height: 34px; border: 0; background: none; cursor: pointer;
            font-size: 12px; font-weight: 700; color: var(--gb-muted);
        }
        .seg + .seg { border-left: 1px solid var(--gb-line); }
        .seg:hover { color: var(--gb-strong); background: var(--gb-surface-2); }
        .seg.active { background: var(--gb-amber); color: var(--gb-amber-ink); }
        .seg.seg-enforce.active { background: var(--gb-bad); color: #fff; }
        .dirty-flag { font-size: 12px; font-weight: 700; color: var(--gb-amber-edge); }
        .status-sentence {
            margin: 12px 0 0; padding: 10px 14px; border-radius: 8px;
            font-size: 13px; line-height: 1.5; color: var(--gb-strong);
            background: var(--gb-tint-ok); border: 1px solid var(--gb-line-ok); border-left-width: 4px;
        }
        .status-sentence.status-off { background: var(--gb-surface-2); border-color: var(--gb-line); color: var(--gb-muted); }
        .status-sentence.status-danger { background: var(--gb-tint-bad); border-color: var(--gb-line-bad); font-weight: 600; }
        .tabs { display: flex; gap: 4px; margin-top: 14px; flex-wrap: wrap; border-top: 1px solid var(--gb-line-soft); padding-top: 12px; }
        .tab {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 7px 14px; min-height: 34px; border-radius: 999px;
            border: 1px solid transparent; background: none; cursor: pointer;
            font-size: 13px; font-weight: 600; color: var(--gb-muted);
            transition: background 0.12s ease, color 0.12s ease;
        }
        .tab:hover { color: var(--gb-strong); background: var(--gb-surface-2); }
        .tab.active { background: var(--gb-amber); border-color: var(--gb-amber-edge); color: var(--gb-amber-ink); }
        .tab-count {
            font-size: 10px; font-weight: 800; min-width: 16px; height: 16px;
            padding: 0 4px; border-radius: 999px; display: inline-grid; place-items: center;
            background: color-mix(in srgb, currentColor 18%, transparent);
        }

        /* ── KPI tiles ────────────────────────────────────────────── */
        .kpi-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
        .kpi { background: var(--gb-surface); border: 1px solid var(--gb-line); border-radius: 12px; padding: 16px 18px; min-width: 0; }
        .kpi-alert { border-color: var(--gb-line-warn); border-left: 4px solid var(--gb-amber); }
        .kpi-label { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--gb-muted); }
        .kpi-num { margin-top: 6px; font-size: 26px; font-weight: 700; line-height: 1.1; color: var(--gb-strong); font-variant-numeric: tabular-nums; letter-spacing: -0.02em; }
        .kpi-sub { margin-top: 4px; font-size: 12px; color: var(--gb-muted); }
        .kpi-sub a { color: var(--gb-amber-edge); font-weight: 600; text-decoration: none; }
        .kpi-sub a:hover { text-decoration: underline; }

        /* ── Overview chart ───────────────────────────────────────── */
        .chart-legend { display: flex; gap: 16px; margin: 4px 0 10px; font-size: 12px; color: var(--gb-muted); }
        .leg { display: inline-flex; align-items: center; gap: 6px; }
        .leg-dot { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }
        .leg-assessed { background: var(--gb-blue); }
        .leg-flagged { background: var(--gb-amber); }
        .bar-chart { display: flex; align-items: flex-end; gap: 6px; height: 160px; padding-top: 8px; overflow-x: auto; }
        .bar-col { flex: 1 1 0; min-width: 26px; display: flex; flex-direction: column; align-items: center; gap: 4px; height: 100%; }
        .bar-stack { position: relative; width: 100%; max-width: 40px; flex: 1 1 auto; display: flex; align-items: flex-end; justify-content: center; }
        .bar { width: 100%; border-radius: 4px 4px 0 0; min-height: 2px; }
        .bar-assessed { background: var(--gb-blue); }
        .bar-flagged { position: absolute; bottom: 0; left: 0; right: 0; background: var(--gb-amber); }
        .bar-label { font-size: 10px; color: var(--gb-muted); white-space: nowrap; }

        /* ── Pills, levels, chips ─────────────────────────────────── */
        .level-rows { display: flex; flex-direction: column; gap: 8px; }
        .level-row { display: flex; align-items: center; gap: 10px; }
        .level-n { font-size: 13px; font-weight: 700; color: var(--gb-strong); font-variant-numeric: tabular-nums; }
        .level-pill {
            font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px;
            color: var(--gb-strong); border: 1px solid var(--gb-line); background: var(--gb-surface-2);
            text-transform: capitalize;
        }
        .lvl-low { background: var(--gb-tint-ok); border-color: var(--gb-line-ok); }
        .lvl-medium { background: var(--gb-tint-info); border-color: var(--gb-line-info); }
        .lvl-review, .lvl-pending { background: var(--gb-tint-warn); border-color: var(--gb-line-warn); }
        .lvl-blocked, .lvl-rejected { background: var(--gb-tint-bad); border-color: var(--gb-line-bad); }
        .lvl-approved { background: var(--gb-tint-ok); border-color: var(--gb-line-ok); }
        .score-pill {
            display: inline-grid; place-items: center; min-width: 34px; height: 26px; padding: 0 6px;
            border-radius: 7px; font-size: 12px; font-weight: 800; font-variant-numeric: tabular-nums;
            color: var(--gb-strong); border: 1px solid var(--gb-line); background: var(--gb-surface-2);
        }
        .score-low { background: var(--gb-tint-ok); border-color: var(--gb-line-ok); }
        .score-mid { background: var(--gb-tint-warn); border-color: var(--gb-line-warn); }
        .score-high { background: var(--gb-tint-bad); border-color: var(--gb-line-bad); }
        .mini-chip {
            font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 5px;
            background: var(--gb-surface); border: 1px solid var(--gb-line-warn);
            color: var(--gb-strong); margin: 1px;
            display: inline-block;
        }
        .signals-cell { max-width: 260px; }
        .reasons-cell { max-width: 300px; }

        /* ── Forms ────────────────────────────────────────────────── */
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px 18px; }
        .form-row label { display: block; font-size: 12px; font-weight: 700; color: var(--gb-strong); margin-bottom: 4px; }
        .form-row label small { font-weight: 500; color: var(--gb-muted); }
        .form-row .form-input { width: 100%; }
        .check-label { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--gb-strong); font-weight: 500; cursor: pointer; }
        .check-label input { accent-color: var(--gb-amber-edge); width: 15px; height: 15px; }
        .mode-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }
        .mode-card {
            display: block; padding: 14px 16px; border-radius: 10px; cursor: pointer;
            border: 1px solid var(--gb-line); background: var(--gb-surface);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .mode-card:hover { border-color: var(--gb-amber-edge); }
        .mode-card.active { border-color: var(--gb-amber-edge); box-shadow: 0 0 0 3px color-mix(in srgb, var(--gb-amber) 30%, transparent); }
        .mode-card:focus-within { outline: 2px solid var(--gb-amber-edge); outline-offset: 2px; }
        .mode-card input { margin-right: 6px; accent-color: var(--gb-amber-edge); }
        .mode-title { font-size: 13px; font-weight: 700; color: var(--gb-strong); display: inline; }
        .mode-body { margin-top: 6px; font-size: 12px; line-height: 1.5; color: var(--gb-muted); }

        /* ── Tables ───────────────────────────────────────────────── */
        .table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .table th {
            text-align: left; font-size: 11px; font-weight: 700; letter-spacing: 0.05em;
            text-transform: uppercase; color: var(--gb-muted);
            padding: 8px 10px; border-bottom: 1px solid var(--gb-line);
        }
        .table td { padding: 9px 10px; border-bottom: 1px solid var(--gb-line-soft); color: var(--gb-strong); vertical-align: top; }
        .table tbody tr:hover { background: var(--gb-surface-2); }
        .table .num-col { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
        .table th.num-col { text-align: right; }
        .mini-track { display: inline-block; height: 6px; flex: 1; background: var(--gb-surface-2); border-radius: 999px; overflow: hidden; }
        .mini-fill { display: block; height: 100%; background: var(--gb-amber); border-radius: 999px; }
        .case-actions { display: flex; gap: 6px; align-items: center; justify-content: flex-end; flex-wrap: wrap; }
        .notes-input { max-width: 130px; min-height: 30px; padding: 4px 8px; font-size: 12px; }
        .case-opts { display: inline-flex; flex-direction: column; gap: 2px; }
        .check-label.check-sm { font-size: 11px; gap: 5px; font-weight: 600; color: var(--gb-muted); white-space: nowrap; }
        .check-label.check-sm input { width: 13px; height: 13px; }
        .picker { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
        .chip-x {
            display: inline-grid; place-items: center; min-width: 22px; min-height: 22px; border-radius: 999px;
            background: none; border: 0; cursor: pointer; font-size: 15px; line-height: 1; padding: 0; color: var(--gb-muted);
        }
        .chip-x:hover { color: var(--gb-danger-ink); background: var(--gb-tint-bad); }

        .subsection-title {
            margin: 20px 0 10px; font-size: 11px; font-weight: 700;
            letter-spacing: 0.06em; text-transform: uppercase; color: var(--gb-muted);
        }
        .subsection-title:first-of-type { margin-top: 4px; }
        .rte { border:1px solid var(--gb-line); border-radius:10px; overflow:hidden; background:var(--gb-surface); margin-bottom:4px; }
        .rte-head { display:flex; align-items:center; justify-content:space-between; gap:8px; padding:6px 8px; background:var(--gb-surface-2); border-bottom:1px solid var(--gb-line); flex-wrap:wrap; }
        .rte-toolbar { display:flex; gap:2px; flex-wrap:wrap; }
        .rte-btn { min-width:30px; height:30px; padding:0 8px; border:1px solid transparent; background:none; border-radius:6px; cursor:pointer; color:var(--gb-strong); font-size:14px; }
        .rte-btn:hover { background:var(--gb-surface); border-color:var(--gb-line); }
        .rte-viewtoggle { display:inline-flex; border:1px solid var(--gb-ui-border); border-radius:999px; overflow:hidden; }
        .rte-tab { padding:4px 12px; border:0; background:none; cursor:pointer; font-size:11px; font-weight:700; color:var(--gb-muted); }
        .rte-tab.active { background:var(--gb-amber); color:var(--gb-amber-ink); }
        .rte-vars { display:flex; align-items:center; gap:6px; flex-wrap:wrap; padding:8px 10px; border-bottom:1px solid var(--gb-line-soft); background:var(--gb-surface); }
        .rte-varlabel { font-size:11px; font-weight:700; color:var(--gb-muted); text-transform:uppercase; letter-spacing:.05em; }
        .rte-chip { font-size:12px; font-weight:600; padding:3px 10px; border-radius:999px; background:var(--gb-tint-info); border:1px solid var(--gb-line-info); color:var(--gb-strong); cursor:grab; user-select:none; }
        .rte-chip:hover { border-color:var(--gb-amber-edge); }
        .rte-editor { min-height:220px; max-height:520px; overflow:auto; margin:12px; padding:16px 18px; background:#fff; color:#0f172a; caret-color:#0f172a; border-radius:8px; box-shadow:0 1px 3px rgba(15,23,42,.14); font-family:Arial,Helvetica,sans-serif; font-size:14px; line-height:1.6; outline:none; }
        :host-context([data-theme='dark']) .rte-editor { box-shadow:0 2px 14px rgba(0,0,0,.5); }
        .rte-editor ::selection { background:#b3d4fc; color:#0f172a; }
        .rte-editor:focus { box-shadow:inset 0 0 0 2px color-mix(in srgb,var(--gb-amber) 30%,transparent); }
        .rte-editor p, .rte-editor li, .rte-editor h1, .rte-editor h2, .rte-editor h3, .rte-editor h4, .rte-editor div, .rte-editor span, .rte-editor strong, .rte-editor em, .rte-editor td, .rte-editor th, .rte-editor blockquote, .rte-editor ul, .rte-editor ol { color: inherit; }
        .rte-editor img { max-width:100%; height:auto; }
        .rte-editor blockquote { border-left:3px solid #cbd5e1; margin:0 0 12px; padding:2px 0 2px 14px; color:#475569; }
        .rte-sep { display:inline-block; width:1px; height:20px; background:var(--gb-line); margin:0 3px; vertical-align:middle; }
        .rte-select { height:30px; border:1px solid var(--gb-line); border-radius:6px; background:var(--gb-surface); color:var(--gb-strong); font-size:12px; padding:0 4px; cursor:pointer; }
        .rte-color { position:relative; overflow:hidden; display:inline-grid; place-items:center; }
        .rte-color input[type=color] { position:absolute; inset:0; width:100%; height:100%; opacity:0; cursor:pointer; border:0; padding:0; }
        .rte-editor h2 { font-size:18px; margin:0 0 8px; } .rte-editor a { color:#2a78d6; }
        .rte-source { width:100%; border:0; padding:14px 16px; background:var(--gb-surface); color:var(--gb-strong); font-family:ui-monospace,monospace; font-size:12px; line-height:1.5; outline:none; resize:vertical; }
        .tpl-preview {
            margin-top: 14px; padding: 16px 18px; border-radius: 10px;
            border: 1px dashed var(--gb-ui-border); background: #fff;
            color: #0f172a; font-size: 13px;
        }
        .tpl-preview-subject { font-weight: 700; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--gb-line); }
        .tpl-list { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
        .tpl-list-row { display: flex; align-items: center; gap: 10px; }
        .tpl-list-row input[type=checkbox] { width: 15px; height: 15px; accent-color: var(--gb-amber-edge); flex: 0 0 auto; }
        .tpl-pick {
            display: flex; align-items: center; gap: 10px; flex: 1;
            padding: 9px 12px; border-radius: 8px; cursor: pointer; text-align: left;
            border: 1px solid var(--gb-line); background: var(--gb-surface); color: var(--gb-strong);
            font-size: 13px; font-weight: 600;
        }
        .tpl-pick:hover { border-color: var(--gb-amber-edge); }
        .tpl-pick.active { border-color: var(--gb-amber-edge); box-shadow: 0 0 0 3px color-mix(in srgb, var(--gb-amber) 25%, transparent); }
        .tpl-pick > span:first-child { flex: 1; }
        .mini-chip.custom { border-color: var(--gb-line-info); }
        .integrations { border: 1px solid var(--gb-line); border-radius: 10px; overflow: hidden; }
        .integ-row + .integ-row { border-top: 1px solid var(--gb-line-soft); }
        .integ-head {
            display: flex; align-items: center; gap: 10px; width: 100%;
            padding: 12px 14px; background: none; border: 0; cursor: pointer;
            text-align: left; color: var(--gb-strong); font-size: 13px;
        }
        .integ-head:hover { background: var(--gb-surface-2); }
        .integ-head:focus-visible { outline: 2px solid var(--gb-amber-edge); outline-offset: -2px; }
        .integ-icon { font-size: 16px; width: 24px; text-align: center; flex: 0 0 auto; }
        .integ-name { font-weight: 700; flex: 0 0 auto; min-width: 110px; }
        .integ-desc { color: var(--gb-muted); font-size: 12px; flex: 1 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .status-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--gb-ui-border); flex: 0 0 auto; }
        .status-dot.on { background: var(--gb-ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--gb-ok) 25%, transparent); }
        .integ-state { font-size: 11px; font-weight: 700; color: var(--gb-muted); flex: 0 0 auto; min-width: 66px; text-align: right; }
        .integ-chev { color: var(--gb-muted); flex: 0 0 auto; }
        .integ-body { padding: 4px 14px 16px 48px; }
        .integ-body .check-label { margin-top: 8px; }

        /* ── Simulate ─────────────────────────────────────────────── */
        .sim-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 14px; }
        .sim-grid label { display: block; font-size: 12px; font-weight: 700; color: var(--gb-strong); margin-bottom: 4px; }
        .sim-grid label small { font-weight: 500; color: var(--gb-muted); }
        .sim-grid .form-input { width: 100%; }
        .sim-result { margin-top: 16px; }
        .sim-banner {
            border-radius: 8px; padding: 12px 14px; font-size: 13px; margin-bottom: 12px;
            color: var(--gb-strong); border: 1px solid; border-left-width: 4px;
        }
        .sim-banner.allow { background: var(--gb-tint-ok); border-color: var(--gb-line-ok); }
        .sim-banner.flag { background: var(--gb-tint-warn); border-color: var(--gb-line-warn); }
        .sim-banner.deny { background: var(--gb-tint-bad); border-color: var(--gb-line-bad); }

        /* ── Save bar + update banner ─────────────────────────────── */
        .save-bar {
            position: sticky; bottom: 12px; z-index: 5;
            display: flex; align-items: center; gap: 10px;
            padding: 12px 16px; border-radius: 12px;
            background: var(--gb-surface); border: 1px solid var(--gb-line);
            box-shadow: var(--gb-shadow-1);
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        .save-bar.is-dirty { border-color: var(--gb-amber-edge); box-shadow: 0 8px 24px rgba(15, 23, 42, 0.18); }
        .save-msg { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; color: var(--gb-strong); }
        .save-msg.quiet { color: var(--gb-muted); font-weight: 500; }
        .save-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--gb-amber); box-shadow: 0 0 0 3px color-mix(in srgb, var(--gb-amber) 25%, transparent); }
        .save-spacer { flex: 1; }
        .update-banner {
            display: flex; gap: 12px; align-items: center; justify-content: space-between; flex-wrap: wrap;
            padding: 12px 16px; border-radius: 10px; font-size: 13px; color: var(--gb-strong);
            background: var(--gb-tint-info); border: 1px solid var(--gb-line-info);
        }
        .update-banner.major { background: var(--gb-tint-warn); border-color: var(--gb-line-warn); }
        .update-banner .actions { display: flex; gap: 6px; align-items: center; }

        @media (prefers-reduced-motion: reduce) {
            .gbtn, .tab, .seg, .mode-card, .save-bar { transition: none; }
        }
        @media (max-width: 640px) {
            .hulo-hero { flex-wrap: wrap; }
            .hulo-hero-actions { width: 100%; justify-content: flex-end; }
            .form-select { min-width: 0; flex: 1; }
            .save-bar { flex-wrap: wrap; }
            .two-col { grid-template-columns: 1fr; }
        }
    `],
})
export class FraudPreventionComponent implements OnInit {
    loading = true;
    helpOpen = false;
    tab: Tab = 'overview';

    meta: any = null;
    configs: FraudConfig[] = [];
    currentIdx = 0;
    dirty = false;
    saving = false;

    modes = [
        { key: 'off' as const, label: 'Off' },
        { key: 'monitor' as const, label: 'Monitor' },
        { key: 'enforce' as const, label: 'Enforce' },
    ];

    stats: any = null;
    statsDays = 7;
    pendingCount = 0;

    cases: any[] = [];
    caseFilters = ['pending', 'approved', 'rejected', ''];
    caseFilter = 'pending';
    caseNotes: Record<number, string> = {};
    caseNotifyOverride: Record<number, boolean> = {};
    caseBlocklist: Record<number, boolean> = {};
    busyCase: number | null = null;

    wl: any[] = [];
    bl: any[] = [];
    listStatus: any = null;
    sources: any[] = [];
    customFeeds: any[] = [];
    newFeed = { name: '', url: '', listType: 'ip' };
    newWl = { type: 'email', value: '', note: '' };
    newBl = { type: 'email', value: '', note: '' };
    syncBusy = false;

    sim = { email: '', ip: '', valueGbp: 100, country: '', newCustomer: false };
    simResult: any = null;
    simBusy = false;

    logRows: any[] = [];
    logLevel = '';
    logAction = '';

    notif: any = null;
    notifDirty = false;

    lookupEmail = '';
    lookupBusy = false;
    profile: any = null;

    advancedOpen = false;
    integOpen = '';
    presets = [
        { key: 'relaxed', label: 'Relaxed', description: 'High-trust store, mostly repeat customers. Only clear-cut fraud patterns are held.',
          values: { reviewThreshold: 55, blockThreshold: 85, maxOrdersPerIpPerHour: 8, maxOrdersPerIpPerDay: 30, maxOrdersPerEmailPerDay: 15, maxOrderValuePence: 1000000, maxDailyValuePerEmailPence: 2000000, requireEmailVerificationAbovePence: 250000 } },
        { key: 'balanced', label: 'Balanced', description: 'Sensible defaults for most stores — catches the classic patterns without bothering real customers.',
          values: { reviewThreshold: 40, blockThreshold: 70, maxOrdersPerIpPerHour: 5, maxOrdersPerIpPerDay: 20, maxOrdersPerEmailPerDay: 10, maxOrderValuePence: 500000, maxDailyValuePerEmailPence: 1000000, requireEmailVerificationAbovePence: 100000 } },
        { key: 'strict', label: 'Strict', description: 'Recently hit by fraud, or high-risk vertical. Expect more reviews — pair with the auto-approve timer.',
          values: { reviewThreshold: 30, blockThreshold: 55, maxOrdersPerIpPerHour: 3, maxOrdersPerIpPerDay: 12, maxOrdersPerEmailPerDay: 6, maxOrderValuePence: 250000, maxDailyValuePerEmailPence: 600000, requireEmailVerificationAbovePence: 50000 } },
    ];

    integrations = [
        { key: 'email', name: 'Email', icon: '✉️', description: 'Admin alerts + customer approval notices via your SMTP' },
        { key: 'slack', name: 'Slack', icon: '💬', description: 'Incoming-webhook message per case event' },
        { key: 'discord', name: 'Discord', icon: '🎮', description: 'Channel webhook message per case event' },
        { key: 'teams', name: 'Teams', icon: '🏢', description: 'Microsoft Teams incoming webhook' },
        { key: 'telegram', name: 'Telegram', icon: '📱', description: 'Bot message to a chat or group' },
        { key: 'webhook', name: 'Webhook', icon: '🔗', description: 'Signed JSON POST for your own systems' },
    ];

    templates: any = null;
    templateKinds = [
        { key: 'held' as const, label: 'Order held' },
        { key: 'approved' as const, label: 'Approved' },
        { key: 'rejected' as const, label: 'Rejected' },
    ];
    tplKind: 'held' | 'approved' | 'rejected' = 'held';
    htmlMode = false;
    lastFocus: 'body' | 'subject' = 'body';
    @ViewChild('emailEditor') emailEditorRef?: ElementRef<HTMLElement>;
    @ViewChild('subjectInput') subjectInputRef?: ElementRef<HTMLInputElement>;
    emailVars = [
        { token: '{{firstName}}', label: 'First name' },
        { token: '{{orderCode}}', label: 'Order code' },
        { token: '{{supportEmail}}', label: 'Support email' },
        { token: '{{reviewHours}}', label: 'Review hours' },
    ];
    tplDirty = false;
    tplPreview: any = null;
    tplSelected: Record<string, boolean> = {};
    get anyTplSelected(): boolean { return this.templateKinds.some(k => this.tplSelected[k.key]); }

    constructor(
        private http: HttpClient,
        private notification: NotificationService,
        private cdr: ChangeDetectorRef,
        private modalService: ModalService,
    ) {}

    get current(): FraudConfig | null {
        return this.configs[this.currentIdx] || null;
    }

    ngOnInit() {
        this.reloadAll();
        this.http.get<any>('/fraud-prevention/meta').subscribe({
            next: m => { this.meta = m; this.cdr.markForCheck(); },
            error: () => undefined,
        });
    }

    reloadAll() {
        this.loading = true;
        this.dirty = false;
        this.http.get<FraudConfig[]>('/fraud-prevention/config').subscribe({
            next: configs => {
                this.configs = configs;
                if (this.currentIdx >= configs.length) this.currentIdx = 0;
                this.loading = false;
                this.loadStats();
                this.loadForTab(this.tab);
                this.cdr.markForCheck();
            },
            error: () => {
                this.loading = false;
                this.notification.error('Failed to load fraud-prevention config');
            },
        });
    }

    onChannelChange() {
        this.dirty = false;
        this.loadForTab(this.tab);
    }

    go(tab: Tab) {
        this.tab = tab;
        this.loadForTab(tab);
    }

    private loadForTab(tab: Tab) {
        if (tab === 'overview') this.loadStats();
        if (tab === 'review') this.loadCases();
        if (tab === 'lists') this.loadLists();
        if (tab === 'activity') this.loadLog();
        if (tab === 'settings') { this.loadNotif(); this.loadTemplates(); }
    }

    // ── Config ─────────────────────────────────────────────────────
    markDirty() { this.dirty = true; }

    setMode(mode: 'off' | 'monitor' | 'enforce') {
        if (!this.current) return;
        if (mode === 'enforce' && this.meta && !this.meta.licensed) {
            this.notification.warning('Enforce mode requires a licence — running in monitor until then.');
        }
        this.current.mode = mode;
        this.markDirty();
    }

    statusSentence(): string {
        const c = this.current;
        if (!c) return '';
        if (c.mode === 'off') return 'Fraud prevention is OFF for this channel — orders are not scored or logged.';
        const thresholds = `review at ${c.reviewThreshold}, block at ${c.blockThreshold}`;
        if (c.mode === 'monitor') {
            return `Monitoring: every order is scored and logged (${thresholds}) but nothing is ever held. Watch Activity, then switch to Enforce when the thresholds look right.`;
        }
        const hold = c.holdFulfilment ? 'licence keys wait for your approval' : 'fulfilment is NOT held (holds disabled)';
        return `Enforcing: orders scoring ≥ ${c.reviewThreshold} are held for review and ${hold}. Orders ≥ ${c.blockThreshold} also tell the customer their order is being verified.`;
    }

    save() {
        if (!this.current) return;
        this.saving = true;
        this.http.post<any>('/fraud-prevention/config', { configs: [this.current] }).subscribe({
            next: () => {
                this.saving = false;
                this.dirty = false;
                this.notification.success('Fraud-prevention settings saved');
                this.cdr.markForCheck();
            },
            error: () => {
                this.saving = false;
                this.notification.error('Save failed');
            },
        });
    }

    // ── Overview ───────────────────────────────────────────────────
    loadStats() {
        this.http.get<any>(`/fraud-prevention/stats?days=${this.statsDays}`).subscribe({
            next: s => {
                this.stats = s;
                this.pendingCount = s.pendingCases || 0;
                this.cdr.markForCheck();
            },
            error: () => undefined,
        });
    }

    barPct(n: number): number {
        const max = Math.max(1, ...(this.stats?.daily || []).map((d: any) => Number(d.assessed || 0)));
        return Math.max(2, (Number(n || 0) / max) * 100);
    }

    levelPct(n: number): number {
        const max = Math.max(1, ...(this.stats?.byLevel || []).map((r: any) => Number(r.n || 0)));
        return Math.max(2, (Number(n || 0) / max) * 100);
    }

    updateAvailable(): boolean {
        return !!(this.meta?.update?.updateAvailable || (this.meta?.update?.latest && this.meta.update.latest !== this.meta.version));
    }

    quickBlockIp(ip: string) {
        this.http.post('/fraud-prevention/lists/blocklist', { type: 'ip', value: ip, note: 'blocked from Overview' }).subscribe({
            next: () => this.notification.success(`Blocked ${ip}`),
            error: () => this.notification.error('Failed to block IP'),
        });
    }

    // ── Review queue ───────────────────────────────────────────────
    loadCases() {
        const run = () => {
            const q = this.caseFilter ? `?status=${this.caseFilter}` : '';
            this.http.get<any[]>(`/fraud-prevention/cases${q}`).subscribe({
                next: rows => {
                    this.cases = rows;
                    // Seed the per-case ticks from the global defaults once, so
                    // the checkboxes bind to plain state (no method-in-binding).
                    const notifyDefault = this.notif ? !!(this.notif.notifyOnApproval || this.notif.notifyOnRejection) : true;
                    const blockDefault = this.notif ? !!this.notif.blocklistOnReject : false;
                    for (const c of rows) {
                        if (this.caseNotifyOverride[c.id] === undefined) this.caseNotifyOverride[c.id] = notifyDefault;
                        if (this.caseBlocklist[c.id] === undefined) this.caseBlocklist[c.id] = blockDefault;
                    }
                    if (this.caseFilter === 'pending') this.pendingCount = rows.length;
                    this.cdr.markForCheck();
                },
                error: () => undefined,
            });
        };
        // Defaults come from notif; load it first if we don't have it yet.
        if (!this.notif) {
            this.http.get<any>('/fraud-prevention/notification-config').subscribe({
                next: n => { this.notif = n; run(); },
                error: () => run(),
            });
        } else {
            run();
        }
    }

    resolveCase(c: any, action: 'approve' | 'reject') {
        this.busyCase = c.id;
        const payload: any = { notes: this.caseNotes[c.id] || '' };
        payload.notifyCustomer = this.caseNotifyOverride[c.id] !== undefined ? this.caseNotifyOverride[c.id] : true;
        if (action === 'reject') payload.blocklistIdentity = !!this.caseBlocklist[c.id];
        this.http.post<any>(`/fraud-prevention/cases/${c.id}/${action}`, payload).subscribe({
            next: r => {
                this.busyCase = null;
                if (r.ok) {
                    const quiet = payload.notifyCustomer === false ? ' (silently)' : '';
                    const banned = r.blocklisted?.length ? ` — ${r.blocklisted.length} identity value(s) blocklisted` : '';
                    this.notification.success(`Case ${action === 'approve' ? 'approved — keys released' : 'rejected — order cancelled'}${quiet}${banned}`);
                    this.loadCases();
                    this.loadStats();
                } else {
                    this.notification.error(r.message || 'Failed');
                }
            },
            error: () => {
                this.busyCase = null;
                this.notification.error('Failed to resolve case');
            },
        });
    }

    parseSignals(raw: any): Array<{ label: string; detail: string }> {
        try {
            const arr = typeof raw === 'string' ? JSON.parse(raw) : raw;
            return Array.isArray(arr) ? arr : [];
        } catch { return []; }
    }

    scoreClass(score: number): string {
        if (score >= (this.current?.blockThreshold ?? 70)) return 'score-high';
        if (score >= (this.current?.reviewThreshold ?? 40)) return 'score-mid';
        return 'score-low';
    }

    // ── Lists ──────────────────────────────────────────────────────
    loadLists() {
        this.http.get<any[]>('/fraud-prevention/lists/whitelist').subscribe({ next: r => { this.wl = r; this.cdr.markForCheck(); }, error: () => undefined });
        this.http.get<any[]>('/fraud-prevention/lists/blocklist').subscribe({ next: r => { this.bl = r; this.cdr.markForCheck(); }, error: () => undefined });
        this.http.get<any>('/fraud-prevention/lists/status').subscribe({ next: r => { this.listStatus = r; this.cdr.markForCheck(); }, error: () => undefined });
        this.http.get<any[]>('/fraud-prevention/lists/sources').subscribe({ next: r => { this.sources = r; this.cdr.markForCheck(); }, error: () => undefined });
        this.http.get<any[]>('/fraud-prevention/feeds/custom').subscribe({ next: r => { this.customFeeds = r; this.cdr.markForCheck(); }, error: () => undefined });
    }

    addEntry(list: 'whitelist' | 'blocklist') {
        const entry = list === 'whitelist' ? this.newWl : this.newBl;
        if (!entry.value) return;
        this.http.post(`/fraud-prevention/lists/${list}`, entry).subscribe({
            next: () => {
                entry.value = ''; entry.note = '';
                this.loadLists();
            },
            error: () => this.notification.error('Failed to add entry'),
        });
    }

    removeEntry(list: 'whitelist' | 'blocklist', id: number) {
        this.http.delete(`/fraud-prevention/lists/${list}/${id}`).subscribe({
            next: () => this.loadLists(),
            error: () => this.notification.error('Failed to remove entry'),
        });
    }

    feedCount(key: string): number {
        const rows = this.listStatus?.lists || [];
        return rows.filter((r: any) => r.source === key).reduce((s: number, r: any) => s + Number(r.entries || 0), 0);
    }

    feedUpdated(key: string): string | null {
        const rows = (this.listStatus?.lists || []).filter((r: any) => r.source === key);
        return rows.length ? rows[0].lastUpdated : null;
    }

    addFeed() {
        if (!this.newFeed.name || !this.newFeed.url) return;
        this.http.post<any>('/fraud-prevention/feeds/custom', this.newFeed).subscribe({
            next: r => {
                if (r.ok) {
                    this.newFeed = { name: '', url: '', listType: 'ip' };
                    this.notification.success('Feed added — syncing…');
                    this.loadLists();
                    if (r.id) this.http.post(`/fraud-prevention/feeds/custom/${r.id}`, { sync: true }).subscribe({ next: () => this.loadLists(), error: () => undefined });
                } else {
                    this.notification.error(r.message || 'Could not add feed');
                }
            },
            error: err => this.notification.error(err?.error?.message || 'Could not add feed'),
        });
    }

    toggleFeed(f: any) {
        this.http.post(`/fraud-prevention/feeds/custom/${f.id}`, { enabled: !f.enabled }).subscribe({
            next: () => { f.enabled = f.enabled ? 0 : 1; },
            error: () => this.notification.error('Failed'),
        });
    }

    syncFeed(f: any) {
        this.syncBusy = true;
        this.http.post<any>(`/fraud-prevention/feeds/custom/${f.id}`, { sync: true }).subscribe({
            next: r => { this.syncBusy = false; r.success ? this.notification.success(r.message) : this.notification.error(r.message); this.loadLists(); },
            error: err => { this.syncBusy = false; this.notification.error(err?.error?.message || 'Sync failed'); },
        });
    }

    removeFeed(f: any) {
        this.http.delete(`/fraud-prevention/feeds/custom/${f.id}`).subscribe({
            next: () => { this.customFeeds = this.customFeeds.filter(x => x.id !== f.id); this.notification.success('Feed removed'); this.cdr.markForCheck(); },
            error: () => this.notification.error('Failed'),
        });
    }

    syncOne(key: string) {
        this.syncBusy = true;
        this.http.post<any>('/fraud-prevention/lists/sync', { sourceKey: key }).subscribe({
            next: r => {
                this.syncBusy = false;
                r.success ? this.notification.success(r.message) : this.notification.error(r.message);
                this.loadLists();
            },
            error: err => {
                this.syncBusy = false;
                this.notification.error(err?.error?.message || 'Sync failed');
            },
        });
    }

    syncAll() {
        this.syncBusy = true;
        this.http.post<any>('/fraud-prevention/lists/sync', {}).subscribe({
            next: r => {
                this.syncBusy = false;
                const ok = (r.results || []).filter((x: any) => x.success).length;
                this.notification.success(`Synced ${ok}/${(r.results || []).length} feeds`);
                this.loadLists();
            },
            error: err => {
                this.syncBusy = false;
                this.notification.error(err?.error?.message || 'Sync failed');
            },
        });
    }

    // ── Simulate ───────────────────────────────────────────────────
    runSim() {
        if (!this.current) return;
        this.simBusy = true;
        this.http.post<any>('/fraud-prevention/simulate', {
            channelId: this.current.channelId,
            email: this.sim.email || undefined,
            ip: this.sim.ip || undefined,
            orderValuePence: Math.round((this.sim.valueGbp || 0) * 100),
            countryCode: this.sim.country || undefined,
            isReturningCustomer: this.sim.newCustomer ? false : undefined,
        }).subscribe({
            next: r => { this.simBusy = false; this.simResult = r; this.cdr.markForCheck(); },
            error: () => { this.simBusy = false; this.notification.error('Simulation failed'); },
        });
    }

    actionSentence(action: string): string {
        switch (action) {
            case 'allow': return 'order flows normally';
            case 'flag': return 'logged as risky (monitor mode — nothing held)';
            case 'review': return 'held for manual review, keys wait for approval';
            case 'block': return 'held + customer told the order is being verified';
            default: return action;
        }
    }

    // ── Activity ───────────────────────────────────────────────────
    loadLog() {
        const params = new URLSearchParams();
        if (this.logLevel) params.set('level', this.logLevel);
        if (this.logAction) params.set('action', this.logAction);
        this.http.get<any[]>(`/fraud-prevention/log?${params}`).subscribe({
            next: rows => { this.logRows = rows; this.cdr.markForCheck(); },
            error: () => undefined,
        });
    }

    // ── Presets + integrations ─────────────────────────────────────
    applyPreset(key: string) {
        const p = this.presets.find(x => x.key === key);
        if (!p || !this.current) return;
        Object.assign(this.current, p.values);
        this.markDirty();
    }

    activePreset(): string {
        const c = this.current;
        if (!c) return 'custom';
        for (const p of this.presets) {
            if (Object.entries(p.values).every(([k, v]) => (c as any)[k] === v)) return p.key;
        }
        return 'custom';
    }

    isConfigured(key: string): boolean {
        const n = this.notif || {};
        switch (key) {
            case 'email': return !!(n.smtpConfigured && n.adminEmail);
            case 'slack': return !!n.slackWebhookUrl;
            case 'discord': return !!n.discordWebhookUrl;
            case 'teams': return !!n.teamsWebhookUrl;
            case 'telegram': return !!(n.telegramBotToken && n.telegramChatId);
            case 'webhook': return !!n.genericWebhookUrl;
            default: return false;
        }
    }

    // ── Lookup ─────────────────────────────────────────────────────
    runLookup() {
        if (!this.lookupEmail) return;
        this.lookupBusy = true;
        this.http.get<any>(`/fraud-prevention/customer-profile?email=${encodeURIComponent(this.lookupEmail)}`).subscribe({
            next: p => { this.lookupBusy = false; this.profile = p; this.cdr.markForCheck(); },
            error: () => { this.lookupBusy = false; this.notification.error('Lookup failed'); },
        });
    }

    lookupListAction(list: 'whitelist' | 'blocklist') {
        if (!this.profile) return;
        this.http.post(`/fraud-prevention/lists/${list}`, { type: 'email', value: this.profile.email, note: 'added from Lookup' }).subscribe({
            next: () => { this.notification.success(`Added to ${list}`); this.runLookup(); },
            error: () => this.notification.error('Failed'),
        });
    }

    exportCsv() {
        const cols = ['createdAt', 'orderCode', 'email', 'ip', 'riskScore', 'riskLevel', 'action', 'reasons'];
        const esc = (v: any) => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const csv = [cols.join(','), ...this.logRows.map(r => cols.map(c => esc(r[c])).join(','))].join('\n');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        a.download = `fraud-log-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    // ── Settings ───────────────────────────────────────────────────
    loadNotif() {
        this.http.get<any>('/fraud-prevention/notification-config').subscribe({
            next: n => { this.notif = n; this.notifDirty = false; this.cdr.markForCheck(); },
            error: () => undefined,
        });
    }

    loadTemplates() {
        if (!this.current) return;
        this.tplPreview = null;
        this.tplDirty = false;
        this.htmlMode = false;
        this.http.get<any>(`/fraud-prevention/templates?channelId=${this.current.channelId}`).subscribe({
            next: t => { this.templates = t; this.cdr.markForCheck(); setTimeout(() => this.syncEditorFromModel(), 0); },
            error: () => undefined,
        });
    }

    // ── Rich email editor ───────────────────────────────────────────
    selectKind(kind: 'held' | 'approved' | 'rejected') { this.tplKind = kind; setTimeout(() => this.syncEditorFromModel(), 0); }
    private editorEl(): HTMLElement | null { return this.emailEditorRef?.nativeElement || null; }
    private syncEditorFromModel() { const ed = this.editorEl(); if (ed && this.templates?.[this.tplKind]) ed.innerHTML = this.templates[this.tplKind].body || ''; }
    onEditorInput() { const ed = this.editorEl(); if (ed && this.templates?.[this.tplKind]) { this.templates[this.tplKind].body = ed.innerHTML; this.tplDirty = true; } }
    setHtmlMode(on: boolean) {
        if (on === this.htmlMode) return;
        if (!on) { this.htmlMode = false; setTimeout(() => this.syncEditorFromModel(), 0); }
        else { this.onEditorInput(); this.htmlMode = true; }
    }
    private savedRange: Range | null = null;
    saveRange() { const sel = window.getSelection(); const ed = this.editorEl(); if (sel && sel.rangeCount && ed && ed.contains(sel.anchorNode)) this.savedRange = sel.getRangeAt(0).cloneRange(); }
    private restoreRange() { const ed = this.editorEl(); if (!ed) return; ed.focus(); if (this.savedRange && ed.contains(this.savedRange.commonAncestorContainer)) { const sel = window.getSelection(); sel?.removeAllRanges(); sel?.addRange(this.savedRange); } }
    exec(cmd: string, val?: string) { const ed = this.editorEl(); if (!ed) return; this.restoreRange(); try { document.execCommand(cmd, false, val); } catch {} this.saveRange(); this.onEditorInput(); }
    pickAsset() {
        const ed = this.editorEl(); if (!ed) return;
        this.modalService.fromComponent(AssetPickerDialogComponent as any, { size: 'xl' }).subscribe((result: any) => {
            if (result && result.length) {
                const imgs = result.map((a: any) => `<img src="${a.preview || a.source}" alt="${String(a.name || '').replace(/"/g, '&quot;')}" style="max-width:100%;height:auto;border-radius:6px">`).join('');
                this.restoreRange();
                try { document.execCommand('insertHTML', false, imgs); } catch {}
                this.onEditorInput();
            }
        });
    }
    setBlock(tag: string) { if (tag) this.exec('formatBlock', '<' + tag + '>'); }
    addLink() { const url = prompt('Link URL', 'https://'); if (url) this.exec('createLink', url); }
    insertImage() {
        const ed = this.editorEl(); if (!ed) return;
        const url = prompt('Image URL (https://…)', 'https://'); if (!url) return;
        const alt = prompt('Alt text (for accessibility)', '') || '';
        this.restoreRange();
        try { document.execCommand('insertHTML', false, `<img src="${url}" alt="${alt.replace(/"/g, '&quot;')}" style="max-width:100%;height:auto;border-radius:6px">`); } catch {}
        this.onEditorInput();
    }
    insertButton() {
        const ed = this.editorEl(); if (!ed) return;
        const label = prompt('Button text', 'Contact us'); if (label === null) return;
        const url = prompt('Button link', 'https://'); if (url === null) return;
        this.restoreRange();
        try { document.execCommand('insertHTML', false, `<p style="text-align:center;margin:18px 0"><a href="${url}" style="display:inline-block;background:#0f172a;color:#fff;text-decoration:none;font-weight:700;font-size:15px;padding:12px 24px;border-radius:8px">${label.replace(/</g, '&lt;')}</a></p>`); } catch {}
        this.onEditorInput();
    }
    onVarDrag(ev: DragEvent, token: string) { ev.dataTransfer?.setData('text/plain', token); }
    onEditorDrop(ev: DragEvent) {
        ev.preventDefault();
        const token = ev.dataTransfer?.getData('text/plain') || ''; if (!token) return;
        const ed = this.editorEl(); if (!ed) return;
        const doc: any = document; let range: Range | null = null;
        if (doc.caretRangeFromPoint) range = doc.caretRangeFromPoint(ev.clientX, ev.clientY);
        else if (doc.caretPositionFromPoint) { const p = doc.caretPositionFromPoint(ev.clientX, ev.clientY); if (p) { range = document.createRange(); range.setStart(p.offsetNode, p.offset); range.collapse(true); } }
        if (range) { const sel = window.getSelection(); sel?.removeAllRanges(); sel?.addRange(range); }
        ed.focus(); try { document.execCommand('insertText', false, token); } catch {} this.onEditorInput();
    }
    insertVar(token: string) {
        if (this.lastFocus === 'subject' && this.subjectInputRef && this.templates?.[this.tplKind]) {
            const el = this.subjectInputRef.nativeElement; const start = el.selectionStart ?? el.value.length; const end = el.selectionEnd ?? start;
            this.templates[this.tplKind].subject = el.value.slice(0, start) + token + el.value.slice(end); this.tplDirty = true;
            setTimeout(() => { el.focus(); const pos = start + token.length; el.setSelectionRange(pos, pos); }, 0);
            return;
        }
        if (this.htmlMode && this.templates?.[this.tplKind]) { this.templates[this.tplKind].body = (this.templates[this.tplKind].body || '') + token; this.tplDirty = true; return; }
        const ed = this.editorEl(); if (!ed) return; ed.focus();
        try { document.execCommand('insertText', false, token); } catch {} this.onEditorInput();
    }

    saveTemplate() {
        if (!this.current || !this.templates) return;
        const t = this.templates[this.tplKind];
        this.http.post('/fraud-prevention/templates', {
            channelId: this.current.channelId, kind: this.tplKind, subject: t.subject, body: t.body,
        }).subscribe({
            next: () => { this.tplDirty = false; this.notification.success('Message saved'); this.loadTemplates(); },
            error: () => this.notification.error('Save failed'),
        });
    }

    resetTemplate() {
        if (!this.current) return;
        this.http.post('/fraud-prevention/templates', {
            channelId: this.current.channelId, kind: this.tplKind, reset: true,
        }).subscribe({
            next: () => { this.notification.success('Reset to default'); this.loadTemplates(); },
            error: () => this.notification.error('Reset failed'),
        });
    }

    resetSelected() {
        if (!this.current) return;
        const kinds = this.templateKinds.filter(k => this.tplSelected[k.key]).map(k => k.key);
        if (!kinds.length) return;
        this.resetKinds(kinds, `${kinds.length} message(s) reset to default`);
    }

    resetAllTemplates() {
        this.resetKinds(this.templateKinds.map(k => k.key), 'All messages reset to default');
    }

    private resetKinds(kinds: string[], successMsg: string) {
        if (!this.current) return;
        const channelId = this.current.channelId;
        let done = 0;
        kinds.forEach(kind => {
            this.http.post('/fraud-prevention/templates', { channelId, kind, reset: true }).subscribe({
                next: () => { if (++done === kinds.length) { this.tplSelected = {}; this.notification.success(successMsg); this.loadTemplates(); } },
                error: () => { if (++done === kinds.length) this.loadTemplates(); this.notification.error('Some resets failed'); },
            });
        });
    }

    previewTemplate() {
        if (!this.current || !this.templates) return;
        const t = this.templates[this.tplKind];
        this.http.post<any>('/fraud-prevention/templates/preview', {
            channelId: this.current.channelId, subject: t.subject, body: t.body,
        }).subscribe({
            next: p => { this.tplPreview = p; this.cdr.markForCheck(); },
            error: () => this.notification.error('Preview failed'),
        });
    }

    saveNotif() {
        this.http.post('/fraud-prevention/notification-config', this.notif).subscribe({
            next: () => { this.notifDirty = false; this.notification.success('Notification settings saved'); },
            error: () => this.notification.error('Save failed'),
        });
    }
}
