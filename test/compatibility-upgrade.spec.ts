import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Pool } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { DatabaseService } from '../src/common/database/database.service';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;

describeWithDatabase('V0 upgraded schema (PostgreSQL integration)', () => {
  let app: INestApplication<App>;
  let pool: Pool;

  beforeAll(async () => {
    if (!databaseUrl) return;
    process.env.DATABASE_URL = databaseUrl;
    process.env.JWT_ACCESS_SECRET = 'disposable-v0-test-secret-long-enough';
    process.env.JWT_ISSUER = 'fintech-v0-compatibility';
    process.env.JWT_AUDIENCE = 'fintech-v0-compatibility';

    pool = new Pool({ connectionString: databaseUrl });
    const database = await pool.query<{ current_database: string }>(
      'SELECT current_database()',
    );
    if (!database.rows[0].current_database.endsWith('_test')) {
      throw new Error(
        'V0 compatibility tests require a disposable _test database',
      );
    }

    const module = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = module.createNestApplication({ logger: false });
    await app.init();
  });

  it('serves readiness from the already-upgraded compatibility marker', async () => {
    await request(app.getHttpServer())
      .get('/ready')
      .expect(200)
      .expect({ status: 'ready' });
  });

  it('applies PostgreSQL statement_timeout to a slow read', async () => {
    const database = app.get(DatabaseService);
    await expect(
      database.queryWithTimeout('SELECT pg_sleep(0.2)', 10),
    ).rejects.toMatchObject({ code: '57014' });
  });

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });
});
