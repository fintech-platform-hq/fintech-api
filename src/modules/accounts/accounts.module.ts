import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../common/database/database.module';
import { AuthModule } from '../auth/auth.module';
import { AccountsController } from './accounts.controller';
import { AccountsService } from './accounts.service';
import { MvpAccountController } from './mvp-account.controller';
import { MvpAccountService } from './mvp-account.service';

@Module({
  imports: [DatabaseModule, AuthModule],
  controllers: [AccountsController, MvpAccountController],
  providers: [AccountsService, MvpAccountService],
})
export class AccountsModule {}
