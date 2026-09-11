interface AccountPersistenceRecord {
  id: string;
  name: string;
  currency: string;
  created_at: Date | string;
}

export class AccountResponseDto {
  id: string;
  name: string;
  currency: string;
  createdAt: string;

  static fromPersistence(
    account: AccountPersistenceRecord,
  ): AccountResponseDto {
    return {
      id: account.id,
      name: account.name,
      currency: account.currency,
      createdAt:
        account.created_at instanceof Date
          ? account.created_at.toISOString()
          : account.created_at,
    };
  }
}
