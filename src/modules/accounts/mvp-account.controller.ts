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
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '../auth/auth.guard';
import type { AuthenticatedRequest } from '../auth/auth.guard';
import { MvpAccountService } from './mvp-account.service';
import { MvpOpeningDto } from './mvp-opening.dto';

@Controller('mvp')
@UseGuards(AuthGuard)
export class MvpAccountController {
  constructor(private readonly accounts: MvpAccountService) {}

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
