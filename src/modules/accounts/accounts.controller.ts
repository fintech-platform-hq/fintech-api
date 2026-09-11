import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '../auth/auth.guard';
import type { AuthenticatedRequest } from '../auth/auth.guard';
import { AccountsService } from './accounts.service';
import { CreateAccountDto } from './dto/create-account.dto';
import { AccountResponseDto } from './dto/account-response.dto';

@Controller('accounts')
@UseGuards(AuthGuard)
export class AccountsController {
  constructor(private readonly accountsService: AccountsService) {}

  @Get()
  listAccounts(
    @Req() request: AuthenticatedRequest,
  ): Promise<AccountResponseDto[]> {
    return this.accountsService.listAccounts(request.principal.userId);
  }

  @Post()
  createAccount(
    @Body() dto: CreateAccountDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<AccountResponseDto> {
    return this.accountsService.createAccount(dto, request.principal.userId);
  }
}
