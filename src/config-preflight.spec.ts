import { spawnSync } from 'child_process';
import { generateKeyPairSync, randomBytes } from 'crypto';
import { join } from 'path';
import { runConfigPreflight } from './config-preflight';

const names = [
  'DATABASE_URL',
  'JWT_ACCESS_SECRET',
  'JWT_ISSUER',
  'JWT_AUDIENCE',
  'LENVER_APPLE_ENVIRONMENT',
  'APPLE_CLIENT_ID',
  'APPLE_TEAM_ID',
  'APPLE_KEY_ID',
  'APPLE_PRIVATE_KEY_P8',
  'APPLE_REFRESH_TOKEN_ENCRYPTION_KEY',
] as const;
const original = new Map(names.map((name) => [name, process.env[name]]));

describe('configuration preflight', () => {
  beforeEach(() => {
    process.env.DATABASE_URL =
      'postgresql://staging_user:staging_password@db.example.test/fintech_staging';
    process.env.JWT_ACCESS_SECRET = randomBytes(32).toString('base64url');
    process.env.JWT_ISSUER = 'fintech-api-staging';
    process.env.JWT_AUDIENCE = 'fintech-clients-staging';
    process.env.LENVER_APPLE_ENVIRONMENT = 'staging';
    process.env.APPLE_CLIENT_ID = 'com.ferrari.lenver.staging';
    process.env.APPLE_TEAM_ID = 'TEAMID1234';
    process.env.APPLE_KEY_ID = 'KEYID12345';
    process.env.APPLE_PRIVATE_KEY_P8 = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    })
      .privateKey.export({ format: 'pem', type: 'pkcs8' })
      .toString();
    process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY =
      randomBytes(32).toString('base64url');
  });

  afterAll(() => {
    for (const [name, value] of original) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  it.each([
    ['staging', 'com.ferrari.lenver.staging'],
    ['production', 'com.ferrari.lenver'],
  ])('reports only boolean readiness for %s', (environment, clientId) => {
    process.env.LENVER_APPLE_ENVIRONMENT = environment;
    process.env.APPLE_CLIENT_ID = clientId;
    expect(runConfigPreflight()).toEqual({
      databaseConfigured: true,
      jwtConfigured: true,
      appleConfigured: true,
    });
  });

  it('fails closed without returning configuration values', () => {
    process.env.DATABASE_URL = 'not-a-database-url';
    process.env.JWT_ACCESS_SECRET = 'short';
    process.env.APPLE_PRIVATE_KEY_P8 = 'private-material-that-must-not-leak';

    const result = runConfigPreflight();

    expect(result).toEqual({
      databaseConfigured: false,
      jwtConfigured: false,
      appleConfigured: false,
    });
    expect(JSON.stringify(result)).not.toContain(process.env.JWT_ACCESS_SECRET);
    expect(JSON.stringify(result)).not.toContain(
      process.env.APPLE_PRIVATE_KEY_P8,
    );
  });

  it.each([
    ['staging', 'com.ferrari.lenver'],
    ['production', 'com.ferrari.lenver.staging'],
    ['staging', 'com.ferrari.Fintech'],
    ['production', 'com.ferrari.Lenver'],
    ['preview', 'com.ferrari.lenver'],
    [undefined, 'com.ferrari.lenver.staging'],
  ])(
    'rejects mismatched Apple configuration %s / %s',
    (environment, clientId) => {
      if (environment === undefined)
        delete process.env.LENVER_APPLE_ENVIRONMENT;
      else process.env.LENVER_APPLE_ENVIRONMENT = environment;
      process.env.APPLE_CLIENT_ID = clientId;

      expect(runConfigPreflight()).toEqual({
        databaseConfigured: true,
        jwtConfigured: true,
        appleConfigured: false,
      });
    },
  );

  it('exits successfully with boolean-only CLI output', () => {
    const result = runCli();

    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      '{"databaseConfigured":true,"jwtConfigured":true,"appleConfigured":true}\n',
    );
    expect(result.stderr).toBe('');
  });

  it('fails the CLI without exposing configuration or internal errors', () => {
    const sensitiveValues = [
      process.env.DATABASE_URL,
      process.env.JWT_ACCESS_SECRET,
      process.env.APPLE_PRIVATE_KEY_P8,
      process.env.APPLE_REFRESH_TOKEN_ENCRYPTION_KEY,
    ];
    process.env.APPLE_PRIVATE_KEY_P8 = 'invalid-private-key-sensitive-value';

    const result = runCli();
    const output = `${result.stdout}${result.stderr}`;

    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe(
      '{"databaseConfigured":true,"jwtConfigured":true,"appleConfigured":false}\n',
    );
    expect(result.stderr).toBe('');
    for (const value of sensitiveValues) expect(output).not.toContain(value);
    expect(output).not.toContain(process.env.APPLE_PRIVATE_KEY_P8);
  });
});

function runCli() {
  return spawnSync(
    process.execPath,
    ['-r', 'ts-node/register', join(process.cwd(), 'src/config-preflight.ts')],
    { env: { ...process.env }, encoding: 'utf8' },
  );
}
