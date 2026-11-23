import {
  Body,
  Controller,
  Get,
  Header,
  Headers,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '../auth/auth.guard';
import type { AuthenticatedRequest } from '../auth/auth.guard';
import { MvpAccountService } from './mvp-account.service';
import { MvpCheckService } from './mvp-check.service';
import {
  MvpCheckConfirmation,
  MvpCheckInput,
  MvpCheckQuery,
} from './mvp-check.dto';
import { MvpOpeningDto } from './mvp-opening.dto';
import { MvpRecoveryInput, MvpRecoveryConfirmation } from './mvp-recovery.dto';
import { MvpRecoveryService } from './mvp-recovery.service';

import { MvpAuditInput, MvpAuditConfirmation } from './mvp-audit.dto';
import { MvpAuditService } from './mvp-audit.service';

@Controller('mvp')
@UseGuards(AuthGuard)
export class MvpAccountController {
  constructor(
    private readonly accounts: MvpAccountService,
    private readonly checks: MvpCheckService,
    private readonly recoveries: MvpRecoveryService,
    private readonly audit: MvpAuditService,
  ) {}

  @Post('audit-previews')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  previewAudit(
    @Req() request: AuthenticatedRequest,
    @Body() dto: MvpAuditInput,
  ) {
    return this.audit.preview(request.principal.userId, dto);
  }

  @Post('audited-changes')
  @Header('Cache-Control', 'no-store')
  confirmAudit(
    @Req() request: AuthenticatedRequest,
    @Headers('idempotency-key') key: string,
    @Body() dto: MvpAuditConfirmation,
  ) {
    return this.audit.confirm(request.principal.userId, key, dto);
  }

  @Get('account/:accountId/base-versions')
  @Header('Cache-Control', 'no-store')
  baseVersions(
    @Req() request: AuthenticatedRequest,
    @Param('accountId', ParseUUIDPipe) accountId: string,
  ) {
    return this.audit.baseVersions(request.principal.userId, accountId);
  }

  @Get('account/:accountId/history/:movementId/versions')
  @Header('Cache-Control', 'no-store')
  movementVersions(
    @Req() request: AuthenticatedRequest,
    @Param('accountId', ParseUUIDPipe) accountId: string,
    @Param('movementId', ParseUUIDPipe) movementId: string,
  ) {
    return this.audit.versions(request.principal.userId, accountId, movementId);
  }

  @Post('recovery-previews')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  previewRecovery(
    @Req() request: AuthenticatedRequest,
    @Body() dto: MvpRecoveryInput,
  ) {
    return this.recoveries.preview(request.principal.userId, dto);
  }

  @Post('recoveries')
  @Header('Cache-Control', 'no-store')
  confirmRecovery(
    @Req() request: AuthenticatedRequest,
    @Headers('idempotency-key') key: string,
    @Body() dto: MvpRecoveryConfirmation,
  ) {
    return this.recoveries.confirm(request.principal.userId, key, dto);
  }

  @Post('check-previews')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  previewCheck(
    @Req() request: AuthenticatedRequest,
    @Body() dto: MvpCheckInput,
  ) {
    return this.checks.preview(request.principal.userId, dto);
  }

  @Post('checks')
  @Header('Cache-Control', 'no-store')
  confirmCheck(
    @Req() request: AuthenticatedRequest,
    @Headers('idempotency-key') key: string,
    @Body() dto: MvpCheckConfirmation,
  ) {
    return this.checks.confirm(request.principal.userId, key, dto);
  }

  @Get('account/:accountId/checks')
  @Header('Cache-Control', 'no-store')
  listChecks(
    @Req() request: AuthenticatedRequest,
    @Param('accountId', ParseUUIDPipe) accountId: string,
    @Query() query: MvpCheckQuery,
  ) {
    return this.checks.list(request.principal.userId, accountId, query);
  }

  @Get('account')
  @Header('Cache-Control', 'no-store')
  read(@Req() request: AuthenticatedRequest) {
    return this.accounts.read(request.principal.userId);
  }

  @Get('account/:accountId')
  @Header('Cache-Control', 'no-store')
  readOwn(
    @Req() request: AuthenticatedRequest,
    @Param('accountId', ParseUUIDPipe) accountId: string,
  ) {
    return this.accounts.read(request.principal.userId, accountId);
  }

  @Get('account/:accountId/history')
  @Header('Cache-Control', 'no-store')
  history(
    @Req() request: AuthenticatedRequest,
    @Param('accountId', ParseUUIDPipe) accountId: string,
    @Query('cursor') cursor?: string,
  ) {
    return this.accounts.history(request.principal.userId, accountId, cursor);
  }

  @Post('account-previews')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  preview(@Req() request: AuthenticatedRequest, @Body() dto: MvpOpeningDto) {
    return this.accounts.preview(request.principal.userId, dto);
  }

  @Post('account')
  @Header('Cache-Control', 'no-store')
  open(
    @Req() request: AuthenticatedRequest,
    @Headers('idempotency-key') key: string,
    @Body() dto: MvpOpeningDto,
  ) {
    return this.accounts.open(request.principal.userId, key, dto);
  }
}
