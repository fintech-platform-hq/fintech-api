import { DatabaseService } from '../../common/database/database.service';
import { MvpCheckService } from './mvp-check.service';

describe('MvpCheckService preview', () => {
  const accountId = '10000000-0000-4000-8000-0000000000AB';
  const userId = '10000000-0000-4000-8000-000000000010';
  const query = jest.fn();
  const service = new MvpCheckService({ query } as unknown as DatabaseService);

  beforeEach(() => query.mockReset());

  it('preserves signed exact results and passes a precise cut to PostgreSQL', async () => {
    query.mockResolvedValue({
      rows: [
        {
          revision: '2',
          covered: true,
          calculatedMinor: '-40',
          differenceMinor: '-9223372036854775847',
        },
      ],
    });
    const result = await service.preview(userId, {
      accountId,
      observedMinor: '9223372036854775807',
      referenceAt: '2026-01-01T12:00:00.123451Z',
    });
    expect(result).toEqual({
      accountId: accountId.toLowerCase(),
      observedMinor: '9223372036854775807',
      referenceAt: '2026-01-01T12:00:00.123451Z',
      revision: '2',
      calculatedMinor: '-40',
      differenceMinor: '-9223372036854775847',
    });
    expect(query).toHaveBeenCalledWith(expect.any(String), [
      userId,
      accountId.toLowerCase(),
      result.referenceAt,
      result.observedMinor,
    ]);
  });

  it('normalizes equivalent UTC precision and rejects an out-of-coverage cut', async () => {
    query.mockResolvedValue({ rows: [{ revision: '1', covered: false }] });
    await expect(
      service.preview(userId, {
        accountId,
        observedMinor: '0',
        referenceAt: '2026-01-01T12:00:00.1Z',
      }),
    ).rejects.toMatchObject({ status: 400 });
    expect(query).toHaveBeenCalledWith(expect.any(String), [
      userId,
      accountId.toLowerCase(),
      '2026-01-01T12:00:00.100000Z',
      '0',
    ]);
  });
});
