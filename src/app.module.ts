import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { TransactionsModule } from './modules/transactions/transactions.module';
import { DatabaseModule } from './common/database/database.module';
import { ErrorLoggingInterceptor } from './common/logging/error-logging.interceptor';
import { RequestLoggingMiddleware } from './common/logging/request-logging.middleware';

@Module({
  imports: [DatabaseModule, TransactionsModule],
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
