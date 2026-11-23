import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../common/database/database.module';
import { TransactionsController } from './transactions.controller';
import { TransactionsService } from './transactions.service';
import { AuthModule } from '../auth/auth.module';
import { MvpTransactionsController } from './mvp-transactions.controller';

@Module({
  imports: [DatabaseModule, AuthModule],
  controllers: [TransactionsController, MvpTransactionsController],
  providers: [TransactionsService],
})
export class TransactionsModule {}
