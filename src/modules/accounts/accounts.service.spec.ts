import { Test, TestingModule } from '@nestjs/testing';
import { DatabaseService } from '../../common/database/database.service';
import { AccountsService } from './accounts.service';

describe('AccountsService', () => {
  type QueryCall = [string, unknown[]?];
  type QueryResult = { rows: unknown[] };

  const userId = '10000000-0000-4000-8000-000000000010';
  const account = {
    id: '10000000-0000-4000-8000-000000000001',
    name: 'Main',
    currency: 'BRL',
    created_at: new Date('2026-09-10T15:00:00.000Z'),
  };

  let service: AccountsService;
  let query: jest.Mock<Promise<QueryResult>, QueryCall>;

  beforeEach(async () => {
    query = jest.fn<Promise<QueryResult>, QueryCall>();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AccountsService,
        { provide: DatabaseService, useValue: { query } },
      ],
    }).compile();

    service = module.get<AccountsService>(AccountsService);
  });

  it('returns an empty list without accounts', async () => {
    query.mockResolvedValue({ rows: [] });

    await expect(service.listAccounts(userId)).resolves.toEqual([]);
    expect(query).toHaveBeenCalledWith(
      expect.stringContaining('WHERE user_id = $1'),
      [userId],
    );
  });

  it('filters account listing by the authenticated user', async () => {
    query.mockResolvedValue({ rows: [account] });

    await expect(service.listAccounts(userId)).resolves.toEqual([
      {
        id: account.id,
        name: account.name,
        currency: account.currency,
        createdAt: account.created_at.toISOString(),
      },
    ]);
    expect(query.mock.calls[0][1]).toEqual([userId]);
  });

  it('creates only an account using the authenticated user id', async () => {
    query.mockResolvedValue({ rows: [account] });

    await expect(
      service.createAccount({ name: 'Main', currency: 'BRL' }, userId),
    ).resolves.toMatchObject({
      id: account.id,
      name: 'Main',
      currency: 'BRL',
    });

    const [sql, parameters] = query.mock.calls[0];
    if (!parameters) {
      throw new Error('Expected account insert parameters');
    }

    expect(parameters).toEqual([expect.any(String), userId, 'Main', 'BRL']);
    expect(sql).toContain('INSERT INTO accounts');
    expect(sql).not.toContain('categories');
    expect(sql).not.toContain('transactions');
  });
});
