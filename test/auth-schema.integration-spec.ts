import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'fs';
import { Pool } from 'pg';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';

const databaseUrl = process.env.TEST_DATABASE_URL;
const describeWithDatabase = databaseUrl ? describe : describe.skip;

describeWithDatabase(
  'Apple authentication schema (PostgreSQL integration)',
  () => {
    let app: INestApplication<App>;
    let pool: Pool;

    beforeAll(async () => {
      process.env.DATABASE_URL = databaseUrl;
      process.env.JWT_ACCESS_SECRET =
        'integration-test-secret-with-at-least-32-bytes';
      process.env.JWT_ISSUER = 'fintech-api-integration';
      process.env.JWT_AUDIENCE = 'fintech-clients-integration';

      pool = new Pool({ connectionString: databaseUrl });
      const database = await pool.query<{ current_database: string }>(
        'SELECT current_database()',
      );
      if (!database.rows[0].current_database.endsWith('_test')) {
        throw new Error('Integration tests require a database ending in _test');
      }

      await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public');
      await pool.query(readFileSync('db.sql', 'utf8'));

      const module = await Test.createTestingModule({
        imports: [AppModule],
      }).compile();
      app = module.createNestApplication();
      app.useGlobalPipes(
        new ValidationPipe({
          whitelist: true,
          forbidNonWhitelisted: true,
          transform: true,
          validationError: { target: false, value: false },
        }),
      );
      await app.init();
    });

    afterAll(async () => {
      await app?.close();
      await pool?.end();
    });

    it('creates an Apple-only user and identity atomically', async () => {
      const userId = '30000000-0000-4000-8000-000000000001';
      const identityId = '30000000-0000-4000-8000-000000000002';
      const client = await pool.connect();

      try {
        await client.query('BEGIN');
        await client.query(
          'INSERT INTO users (id, email, password_hash) VALUES ($1, NULL, NULL)',
          [userId],
        );
        await client.query(
          `INSERT INTO auth_identities (
          id, user_id, provider, provider_subject
        ) VALUES ($1, $2, 'apple', $3)`,
          [identityId, userId, 'apple-sub-atomic'],
        );
        await client.query('COMMIT');
      } finally {
        client.release();
      }

      const result = await pool.query<{ user_id: string }>(
        'SELECT user_id FROM auth_identities WHERE id = $1',
        [identityId],
      );
      expect(result.rows[0].user_id).toBe(userId);
    });

    it('rejects a user without a password or identity at commit', async () => {
      const client = await pool.connect();

      try {
        await client.query('BEGIN');
        await client.query(
          'INSERT INTO users (id, email, password_hash) VALUES ($1, NULL, NULL)',
          ['30000000-0000-4000-8000-000000000003'],
        );
        await expect(client.query('COMMIT')).rejects.toMatchObject({
          code: '23514',
        });
        await client.query('ROLLBACK');
      } finally {
        client.release();
      }
    });

    it('rejects duplicate Apple identities and cross-user session ownership', async () => {
      const firstUserId = '30000000-0000-4000-8000-000000000004';
      const secondUserId = '30000000-0000-4000-8000-000000000005';
      const identityId = '30000000-0000-4000-8000-000000000006';

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `INSERT INTO users (id, email, password_hash)
         VALUES ($1, $2, NULL), ($3, $4, $5)`,
          [
            firstUserId,
            'relay-one@privaterelay.appleid.com',
            secondUserId,
            'relay-two@privaterelay.appleid.com',
            'test-password-hash',
          ],
        );
        await client.query(
          `INSERT INTO auth_identities (id, user_id, provider, provider_subject)
         VALUES ($1, $2, 'apple', $3)`,
          [identityId, firstUserId, 'apple-sub-unique'],
        );
        await client.query('COMMIT');
      } finally {
        client.release();
      }

      await expect(
        pool.query(
          `INSERT INTO auth_identities (id, user_id, provider, provider_subject)
         VALUES ($1, $2, 'apple', $3)`,
          [
            '30000000-0000-4000-8000-000000000007',
            secondUserId,
            'apple-sub-unique',
          ],
        ),
      ).rejects.toMatchObject({ code: '23505' });

      await expect(
        pool.query(
          `INSERT INTO refresh_sessions (
          id, user_id, auth_identity_id, family_id, token_hash, expires_at
        ) VALUES ($1, $2, $3, $4, $5, now() + interval '30 days')`,
          [
            '30000000-0000-4000-8000-000000000008',
            secondUserId,
            identityId,
            '30000000-0000-4000-8000-000000000009',
            '3000000000000000000000000000000000000000000000000000000000000001',
          ],
        ),
      ).rejects.toMatchObject({ code: '23503' });
    });

    it('treats an Apple-only email as invalid for password login', async () => {
      const passwordLogin = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: 'relay-one@privaterelay.appleid.com',
          password: 'correct horse',
        });

      expect(passwordLogin.status).toBe(401);
    });
  },
);
