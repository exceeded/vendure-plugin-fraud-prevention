import { NgModule } from '@angular/core';
import { SharedModule, addNavMenuItem, registerDashboardWidget } from '@vendure/admin-ui/core';

/**
 * Registers the "Fraud Prevention" entry in the admin nav (Sales section —
 * next to Orders, where the review queue is worked from) and the dashboard
 * widget (Dashboard → Add widget → Fraud Prevention). Both require the same
 * read permission as the page itself.
 */
@NgModule({
    imports: [SharedModule],
    providers: [
        addNavMenuItem(
            {
                id: 'hulo-vendure-plugin-fraud-prevention',
                label: 'Fraud Prevention',
                routerLink: ['/extensions/fraud-prevention'],
                icon: 'shield-check',
                requiresPermission: 'ReadCatalog',
            },
            'sales',
        ),
        registerDashboardWidget('hulo-vendure-plugin-fraud-prevention', {
            title: 'Fraud Prevention',
            supportedWidths: [4, 6, 8],
            requiresPermissions: ['ReadCatalog'],
            loadComponent: () => import('./components/fraud-prevention-widget.component').then(m => m.FraudPreventionWidgetComponent),
        }),
    ],
})
export class FraudPreventionNavModule {}
