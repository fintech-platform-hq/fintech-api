import { ServiceUnavailableException } from '@nestjs/common';
import { DatabaseService } from './common/database/database.service';
import { AppController } from './app.controller';

describe('AppController', () => {
  it('keeps liveness independent from database readiness', async () => {
    const database = {
      queryWithTimeout: jest
        .fn()
        .mockRejectedValue(new Error('database unavailable')),
    } as unknown as DatabaseService;
    const controller = new AppController(database);

    expect(controller.getServiceStatus()).toEqual({
      name: 'lenver-api',
      status: 'running',
    });
    expect(controller.getHealth()).toEqual({ status: 'ok' });
    await expect(controller.getReadiness()).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it('reports ready only for the compatible database schema', async () => {
    const queryWithTimeout = jest
      .fn()
      .mockResolvedValue({ rows: [{ version: '20261127_v1_method_receipts' }] });
    const database = { queryWithTimeout } as unknown as DatabaseService;
    const controller = new AppController(database);

    await expect(controller.getReadiness()).resolves.toEqual({
      status: 'ready',
    });
    expect(queryWithTimeout).toHaveBeenCalledWith(
      'SELECT version FROM lenver_schema_version WHERE singleton = true',
      1_500,
    );
  });

  it.each([
    { rows: [] },
    { rows: [{ version: 'older' }] },
    new Error('database details must not escape'),
  ])(
    'returns a generic unavailable response for incompatible readiness',
    async (result) => {
      const database = {
        queryWithTimeout: jest
          .fn()
          .mockImplementation(() =>
            result instanceof Error
              ? Promise.reject(result)
              : Promise.resolve(result),
          ),
      } as unknown as DatabaseService;
      const controller = new AppController(database);

      await expect(controller.getReadiness()).rejects.toMatchObject({
        status: 503,
        response: { status: 'not_ready' },
      });
    },
  );
});
