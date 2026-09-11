import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { DatabaseService } from '../../common/database/database.service';
import { CreateAccountDto } from './dto/create-account.dto';
import { AccountResponseDto } from './dto/account-response.dto';

interface AccountPersistenceRecord {
  id: string;
  name: string;
  currency: string;
  created_at: Date | string;
}

@Injectable()
export class AccountsService {
  constructor(private readonly db: DatabaseService) {}

  async listAccounts(userId: string): Promise<AccountResponseDto[]> {
    const result = await this.db.query<AccountPersistenceRecord>(
      `
        SELECT id, name, currency, created_at
        FROM accounts
        WHERE user_id = $1
        ORDER BY created_at ASC, id ASC
      `,
      [userId],
    );

    return result.rows.map((account) =>
      AccountResponseDto.fromPersistence(account),
    );
  }

  async createAccount(
    dto: CreateAccountDto,
    userId: string,
  ): Promise<AccountResponseDto> {
    const result = await this.db.query<AccountPersistenceRecord>(
      `
        INSERT INTO accounts (id, user_id, name, currency)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, currency, created_at
      `,
      [randomUUID(), userId, dto.name, dto.currency],
    );

    return AccountResponseDto.fromPersistence(result.rows[0]);
  }
}
