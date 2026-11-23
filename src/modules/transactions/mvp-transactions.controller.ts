import {
  Body,
  Controller,
  Header,
  Headers,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '../auth/auth.guard';
import type { AuthenticatedRequest } from '../auth/auth.guard';
import { MvpTransactionDto } from './dto/mvp-transaction.dto';
import { TransactionsService } from './transactions.service';

@Controller('mvp/transactions')
@UseGuards(AuthGuard)
export class MvpTransactionsController {
  constructor(private readonly transactions: TransactionsService) {}

  @Post()
  @Header('Cache-Control', 'no-store')
  register(
    @Body() dto: MvpTransactionDto,
    @Headers('idempotency-key') key: string,
    @Req() request: AuthenticatedRequest,
  ) {
    return this.transactions.registerMvp(dto, key, request.principal.userId);
  }
}
