import { Module } from '@nestjs/common';
import { TransactionsModule } from './modules/transactions/transactions.module';
import { DatabaseModule } from './common/database/database.module';

@Module({
  imports: [DatabaseModule, TransactionsModule],
})
export class AppModule {}
