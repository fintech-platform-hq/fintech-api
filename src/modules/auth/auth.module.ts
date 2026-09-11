import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { DatabaseModule } from '../../common/database/database.module';
import { AppleApiClient } from './apple-api.client';
import { AppleClientSecretService } from './apple-client-secret.service';
import { AppleIdentityTokenVerifier } from './apple-identity-token.verifier';
import { AppleJwksService } from './apple-jwks.service';
import { AuthConfig } from './auth.config';
import { AuthController } from './auth.controller';
import { AuthGuard } from './auth.guard';
import { AuthRateLimitMiddleware } from './auth-rate-limit.middleware';
import { AuthService } from './auth.service';

@Module({
  imports: [DatabaseModule],
  controllers: [AuthController],
  providers: [
    AuthConfig,
    AuthService,
    AuthGuard,
    AuthRateLimitMiddleware,
    AppleApiClient,
    AppleJwksService,
    AppleIdentityTokenVerifier,
    AppleClientSecretService,
  ],
  exports: [AuthGuard, AuthService],
})
export class AuthModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AuthRateLimitMiddleware).forRoutes(AuthController);
  }
}
