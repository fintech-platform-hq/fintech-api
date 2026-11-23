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

@Controller('mvp')
@UseGuards(AuthGuard)
export class MvpAccountController {
  constructor(
    private readonly accounts: MvpAccountService,
    private readonly checks: MvpCheckService,
  ) {}

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
