import { BadRequestException, NotFoundException } from '@nestjs/common';
import { DatabaseService } from '../../common/database/database.service';
import { MvpRecoveryService } from './mvp-recovery.service';

describe('MvpRecoveryService preview', () => {
  const account = '10000000-0000-4000-8000-000000000001';
  const check = '10000000-0000-4000-8000-000000000002';
  const user = '10000000-0000-4000-8000-000000000003';
  const input = {
    accountId: account,
    checkId: check,
    day: '2026-11-15',
    amountMinor: '2500',
  };
  let query: jest.Mock;
  let service: MvpRecoveryService;

  beforeEach(() => {
    query = jest.fn().mockResolvedValue({
      rows: [{ accountId: account, checkId: check, revision: '4' }],
    });
    service = new MvpRecoveryService({ query } as unknown as DatabaseService);
  });

  it('keeps civil dates without assigning a timestamp and passes only a supplied external reference', async () => {
    await service.preview(user, { ...input, description: ' Padaria ' });
    expect(query).toHaveBeenCalledWith(expect.any(String), [
      user,
      account,
      check,
      '2500',
      '2026-11-15',
      null,
      'Padaria',
      null,
      null,
    ]);
    await service.preview(user, {
      ...input,
      occurredAt: '2026-11-15T15:00:00.123Z',
      externalSource: 'bank-a',
      externalReference: ' Fk-12 ',
    });
    expect(query).toHaveBeenLastCalledWith(expect.any(String), [
      user,
      account,
      check,
      '2500',
      '2026-11-15',
      '2026-11-15T15:00:00.123000Z',
      null,
      'bank-a',
      'Fk-12',
    ]);
  });

  it('rejects the incomplete external reference before querying and conceals unowned checks', async () => {
    await expect(
      service.preview(user, { ...input, externalSource: 'bank-a' }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(query).not.toHaveBeenCalled();
    query.mockResolvedValueOnce({ rows: [] });
    await expect(service.preview(user, input)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});
