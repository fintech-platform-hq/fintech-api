import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../common/database/database.module';
import { AuthModule } from '../auth/auth.module';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { MvpAccountController } from './mvp-account.controller';
import { MvpAccountService } from './mvp-account.service';
import { MvpCheckService } from './mvp-check.service';
import { MvpRecoveryService } from './mvp-recovery.service';

import { MvpAuditService } from './mvp-audit.service';

@Module({
  imports: [DatabaseModule, AuthModule],
  controllers: [AccountsController, MvpAccountController],
  providers: [
    AccountsService,
    MvpAccountService,
    MvpCheckService,
    MvpRecoveryService,
    MvpAuditService,
  ],
})
export class AccountsModule {}
