import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { DatabaseService } from '../../common/database/database.service';
import { sessionAuthority } from './session-authority';
import { AuthPrincipal } from './auth.types';

export type AuthenticatedRequest = Request & { principal: AuthPrincipal };

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly db: DatabaseService,
  ) {}

  protected readonly requiresFinancialAuthority: boolean = true;

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    http.getResponse<Response>().setHeader('Cache-Control', 'no-store');
    const request = http.getRequest<AuthenticatedRequest>();
    const authorization = request.headers.authorization;

    if (!authorization?.startsWith('Bearer ')) {
      throw new UnauthorizedException();
    }

    request.principal = this.authService.verifyAccessToken(
      authorization.slice('Bearer '.length),
    );
    await sessionAuthority(
      this.db,
      request.principal,
      this.requiresFinancialAuthority,
    );
    return true;
  }
}

@Injectable()
export class IdentityGuard extends AuthGuard {
  protected readonly requiresFinancialAuthority = false;
}
