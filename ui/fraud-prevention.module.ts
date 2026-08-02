import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';
import { SharedModule } from '@vendure/admin-ui/core';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { FraudPreventionComponent } from './components/fraud-prevention.component';

@NgModule({
    imports: [
        SharedModule, FormsModule, HttpClientModule,
        RouterModule.forChild([
            { path: '', pathMatch: 'full', component: FraudPreventionComponent, data: { breadcrumb: 'Fraud prevention' } },
        ]),
    ],
    declarations: [FraudPreventionComponent],
})
export class FraudPreventionModule {}
