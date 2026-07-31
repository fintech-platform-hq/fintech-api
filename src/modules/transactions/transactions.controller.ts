import { Body, Controller, Headers, Post } from '@nestjs/common';
import { TransactionsService } from './transactions.service';
import { CreateTransactionDto } from './dto/create-transaction.dto';
import { TransactionResponseDto } from './dto/transaction-response.dto';

@Controller('transactions')
export class TransactionsController {
  constructor(private readonly transactionsService: TransactionsService) {}

  @Post()
  createTransaction(
    @Body() dto: CreateTransactionDto,
    @Headers('idempotency-key') idempotencyKey: string,
  ): Promise<TransactionResponseDto> {
    return this.transactionsService.createTransaction(dto, idempotencyKey);
  }
}
