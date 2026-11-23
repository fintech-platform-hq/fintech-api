import { randomUUID } from 'node:crypto';
import type { DatabaseService } from '../../common/database/database.service';
import type { AuthConfig } from '../auth/auth.config';
import type { MvpAuditInput } from './mvp-audit.dto';
import { MvpAuditService } from './mvp-audit.service';

describe('I5 base audit', () => {
  const holder = randomUUID();
  const accountId = randomUUID();
  const input: MvpAuditInput = {
    accountId,
    targetId: accountId,
    action: 'correct_base',
    reason: 'Fictitious review',
    baseMinor: '0',
  };
  const query = jest.fn();
  const getClient = jest.fn();
  const service = new MvpAuditService(
    { query, getClient } as unknown as DatabaseService,
    { jwtSecret: 'fictional-i5-secret' } as AuthConfig,
  );

  beforeEach(() => jest.resetAllMocks());

  it.each([
    { baseMinor: '9223372036854775808' },
    { baseMinor: undefined, coverageStart: '2026-01-01T01:00:00Z' },
    { targetId: randomUUID() },
    { reason: '   ' },
    { action: 'suspend_base', baseMinor: '0' },
  ] satisfies Partial<MvpAuditInput>[])(
    'rejects invalid terms before querying: %o',
    async (fields) => {
      await expect(
        service.preview(holder, { ...input, ...fields }),
      ).rejects.toMatchObject({ status: 400 });
      expect(query).not.toHaveBeenCalled();
    },
  );

  it('requires an explicit confirmation before opening a transaction', async () => {
    await expect(
      service.confirm(holder, randomUUID(), {
        ...input,
        expectedRevision: '1',
        previewToken: '0'.repeat(64),
      }),
    ).rejects.toMatchObject({ status: 400 });
    expect(getClient).not.toHaveBeenCalled();
  });

  it('returns a projected suspension for an ambiguous instant without a confirmation token', async () => {
    const ambiguousMovementIds = [randomUUID()];
    query.mockResolvedValueOnce({
      rows: [
        {
          revision: '5',
          changed: true,
          covered: true,
          balanceMinor: '1',
          projectedBalanceMinor: null,
          ambiguousMovementIds,
          checks: [],
        },
      ],
    });
    await expect(service.preview(holder, input)).resolves.toMatchObject({
      revision: '5',
      balanceMinor: '1',
      projectedBalanceMinor: null,
      previewToken: null,
      ambiguousMovementIds,
    });
  });
});
