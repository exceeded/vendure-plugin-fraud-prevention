import { NgModule } from '@angular/core';
import { SharedModule, registerCustomDetailComponent } from '@vendure/admin-ui/core';
import { OrderFraudPanelComponent } from './components/order-fraud-panel.component';

/**
 * Embeds the fraud-score panel on the admin order-detail page.
 * The panel itself only renders once the order is paid.
 */
@NgModule({
    imports: [SharedModule],
    providers: [
        registerCustomDetailComponent({
            locationId: 'order-detail',
            component: OrderFraudPanelComponent,
        }),
    ],
})
export class OrderFraudSharedModule {}
