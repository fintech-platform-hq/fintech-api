import {
  BadRequestException,
  Body,
  Get,
  Param,
  ParseUUIDPipe,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { isUUID } from 'class-validator';
import { AuthService } from './auth.service';
import { AuthResponse } from './auth.types';
import { IdentityGuard } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';
import { CredentialsDto } from './dto/credentials.dto';
import { AppleAuthenticationDto } from './dto/apple-authentication.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

import { IdentityService } from './identity.service';
import {
  AppleLinkDto,
  ChangePendingEmailDto,
  CommitPasswordChangeDto,
  EmailDto,
  EmailProofDto,
  RequestPasswordLinkDto,
  PasswordProofDto,
  PreparePasswordChangeDto,
  ResetPasswordDto,
} from './dto/identity.dto';

@Controller(['v1/auth', 'auth'])
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly identity: IdentityService,
  ) {}

  @Post('register')
  register(@Body() dto: CredentialsDto): Promise<AuthResponse> {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: CredentialsDto): Promise<AuthResponse> {
    return this.authService.login(dto);
  }

  @Post('apple')
  @HttpCode(HttpStatus.OK)
  apple(@Body() dto: AppleAuthenticationDto): Promise<AuthResponse> {
    return this.authService.apple(dto);
  }

  @Post('apple/link')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  linkApple(
    @Body() dto: AppleLinkDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<void> {
    if (!dto.consent) throw new BadRequestException('Consent required');
    return this.authService.linkApple(
      request.principal,
      dto,
      dto.password,
      this.methodOperationId(request),
    );
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() dto: RefreshTokenDto): Promise<AuthResponse> {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Body() dto: RefreshTokenDto): Promise<void> {
    await this.authService.logout(dto.refreshToken);
  }

  @Get('session')
  @UseGuards(IdentityGuard)
  session(@Req() request: AuthenticatedRequest) {
    return this.identity.status(request.principal);
  }

  @Post('verification')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.ACCEPTED)
  requestVerification(@Req() request: AuthenticatedRequest) {
    return this.identity.requestVerification(request.principal);
  }

  @Post('verification/confirm')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  confirmVerification(
    @Req() request: AuthenticatedRequest,
    @Body() dto: EmailProofDto,
  ) {
    return this.identity.verifyEmail(request.principal, dto.code);
  }

  @Post('recovery')
  @HttpCode(HttpStatus.ACCEPTED)
  requestRecovery(@Body() dto: EmailDto) {
    return this.identity.requestRecovery(dto.email);
  }

  @Post('recovery/confirm')
  @HttpCode(HttpStatus.NO_CONTENT)
  confirmRecovery(@Body() dto: ResetPasswordDto) {
    return this.identity.resetPassword(dto.email, dto.code, dto.newPassword);
  }

  @Post('apple/unlink')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  unlinkApple(
    @Req() request: AuthenticatedRequest,
    @Body() dto: PasswordProofDto,
  ) {
    return this.authService.unlinkApple(
      request.principal,
      dto.password,
      this.methodOperationId(request),
    );
  }

  @Post('verification/email')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  changePendingEmail(
    @Req() request: AuthenticatedRequest,
    @Body() dto: ChangePendingEmailDto,
  ) {
    return this.identity.changePendingEmail(
      request.principal,
      dto.email,
      dto.password,
    );
  }

  @Post('password/link')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.ACCEPTED)
  requestPasswordLink(
    @Req() request: AuthenticatedRequest,
    @Body() dto: RequestPasswordLinkDto,
  ) {
    if (!dto.consent) throw new BadRequestException('Consent required');
    return this.identity.requestPasswordLink(request.principal, dto.email, dto);
  }

  @Post('password/link/confirm')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  linkPassword(
    @Req() request: AuthenticatedRequest,
    @Body() dto: ResetPasswordDto,
  ) {
    return this.identity.linkPassword(
      request.principal,
      dto.email,
      dto.code,
      dto.newPassword,
      this.methodOperationId(request),
    );
  }

  @Post('password/unlink')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  unlinkPassword(
    @Req() request: AuthenticatedRequest,
    @Body() dto: AppleAuthenticationDto,
  ) {
    return this.identity.unlinkPassword(
      request.principal,
      dto,
      this.methodOperationId(request),
    );
  }

  @Get('method-operations/:operationId')
  @UseGuards(IdentityGuard)
  methodOutcome(
    @Req() request: AuthenticatedRequest,
    @Param('operationId', ParseUUIDPipe) operationId: string,
  ) {
    return this.identity.methodOutcome(request.principal, operationId);
  }

  private methodOperationId(request: AuthenticatedRequest): string | undefined {
    const key = request.headers['idempotency-key'];
    if (key === undefined) return;
    if (typeof key !== 'string' || !isUUID(key)) {
      throw new BadRequestException('Idempotency-Key must be a UUID');
    }
    return key;
  }

  @Post('password/change/proof')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.OK)
  passwordChangeProof(
    @Req() request: AuthenticatedRequest,
    @Body() dto: PreparePasswordChangeDto,
  ) {
    return this.identity.prepareChange(
      request.principal,
      dto.operationId,
      dto.password,
    );
  }

  @Post('password/change')
  @UseGuards(IdentityGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  changePassword(
    @Req() request: AuthenticatedRequest,
    @Body() dto: CommitPasswordChangeDto,
  ) {
    return this.identity.changePassword(
      request.principal,
      dto.operationId,
      dto.proof,
      dto.newPassword,
    );
  }

  @Get('password/change/:operationId')
  @UseGuards(IdentityGuard)
  changeOutcome(
    @Req() request: AuthenticatedRequest,
    @Param('operationId', ParseUUIDPipe) operationId: string,
  ) {
    return this.identity.changeOutcome(request.principal, operationId);
  }
}
