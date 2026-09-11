import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { TransactionsModule } from './modules/transactions/transactions.module';
import { DatabaseModule } from './common/database/database.module';
import { ErrorLoggingInterceptor } from './common/logging/error-logging.interceptor';
import { RequestLoggingMiddleware } from './common/logging/request-logging.middleware';
import { AppController } from './app.controller';
import { AuthModule } from './modules/auth/auth.module';
import { AccountsModule } from './modules/accounts/accounts.module';

@Module({
  imports: [DatabaseModule, AuthModule, AccountsModule, TransactionsModule],
  controllers: [AppController],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: ErrorLoggingInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestLoggingMiddleware).forRoutes('*');
  }
}
