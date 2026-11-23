const { readFileSync } = require('node:fs');
const { request } = require('node:http');
const { createServer } = require('node:https');
const { join } = require('node:path');
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { ValidationPipe } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('../../dist/app.module');

const upstream = 'http://127.0.0.1:55455';
const password = 'fictional i4 password';

async function post(path, data, token) {
  const response = await fetch(upstream + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token
        ? { Authorization: `Bearer ${token}`, 'Idempotency-Key': randomUUID() }
        : {}),
    },
    body: JSON.stringify(data),
  });
  if (response.status !== 201)
    throw new Error(`Fixture setup failed at ${path} (${response.status})`);
  return response.json();
}

async function seed(email) {
  const { accessToken } = await post('/auth/register', { email, password });
  const { account } = await post(
    '/mvp/account',
    {
      coverageStart: '2026-11-14T12:00:00Z',
      baseMinor: '90000',
      referenceZone: 'America/Sao_Paulo',
    },
    accessToken,
  );
  const accountId = account.id;
  const referenceAt = '2026-11-18T12:00:00Z';
  async function expense(
    amountMinor,
    occurredAt,
    description,
    expectedRevision,
  ) {
    await post(
      '/mvp/transactions',
      {
        accountId,
        amountMinor,
        occurredAt,
        description,
        type: 'expense',
        currency: 'BRL',
        expectedRevision,
        clientMutationId: randomUUID(),
      },
      accessToken,
    );
  }
  await expense(5500, '2026-11-18T10:00:00Z', 'Despesa anterior', '1');
  const check = await post(
    '/mvp/checks',
    { accountId, observedMinor: '80000', referenceAt, expectedRevision: '2' },
    accessToken,
  );
  await expense(1800, '2026-11-18T12:10:00Z', 'Café depois do corte', '3');
  const recovery = {
    accountId,
    checkId: check.id,
    action: 'create',
    evidence: 'Comprovante fictício',
  };
  await post(
    '/mvp/recoveries',
    {
      ...recovery,
      expectedRevision: '4',
      amountMinor: '2500',
      day: '2026-11-15',
      occurredAt: '2026-11-15T15:00:00Z',
      description: 'Padaria I4',
    },
    accessToken,
  );
  await post(
    '/mvp/recoveries',
    {
      ...recovery,
      expectedRevision: '5',
      amountMinor: '2000',
      day: '2026-11-16',
      occurredAt: '2026-11-16T15:00:00Z',
      description: 'Despesa duplicada I4',
    },
    accessToken,
  );
}

async function main() {
  const db = new URL(process.env.DATABASE_URL);
  const tls = process.env.I4_TLS_DIR;
  if (
    db.protocol !== 'postgresql:' ||
    db.hostname !== '127.0.0.1' ||
    !db.pathname.endsWith('_test') ||
    !tls
  ) {
    throw new Error('Use a loopback test database and local TLS files');
  }

  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.enableShutdownHooks();
  await app.listen(55455, '127.0.0.1');
  if (process.env.I4_SEED === '1') {
    await seed('i4-a@example.test');
    await seed('i4-b@example.test');
  }

  let interrupted;
  let release = false;
  let replayed = false;
  const server = createServer(
    {
      key: readFileSync(join(tls, 'localhost.key')),
      cert: readFileSync(join(tls, 'localhost.pem')),
    },
    (incoming, outgoing) => {
      if (incoming.method === 'POST' && incoming.url === '/__i4/release') {
        release = true;
        return outgoing.writeHead(204).end();
      }
      if (incoming.method === 'GET' && incoming.url === '/__i4/replay') {
        return outgoing
          .writeHead(200)
          .end(replayed ? 'verified' : interrupted ? 'interrupted' : 'pending');
      }
      const chunks = [];
      incoming.on('data', (chunk) => chunks.push(chunk));
      incoming.on('end', () => {
        const body = Buffer.concat(chunks);
        const proxied = request(
          upstream + incoming.url,
          {
            method: incoming.method,
            headers: incoming.headers,
          },
          (reply) => {
            const parts = [];
            reply.on('data', (part) => parts.push(part));
            reply.on('end', () => {
              const response = Buffer.concat(parts);
              if (
                incoming.method === 'POST' &&
                incoming.url === '/mvp/audited-changes' &&
                reply.statusCode === 201 &&
                JSON.parse(body).action === 'correct'
              ) {
                const key = incoming.headers['idempotency-key'];
                const receipt = JSON.parse(response);
                if (!interrupted) {
                  interrupted = { key, body, receipt };
                  console.log(
                    'I4 correction committed; HTTPS response intentionally dropped',
                  );
                } else if (
                  key !== interrupted.key ||
                  !interrupted.body.equals(body) ||
                  !isDeepStrictEqual(interrupted.receipt, receipt)
                ) {
                  return outgoing.writeHead(500).end();
                }
                if (!release) return incoming.socket.destroy();
                replayed = true;
                console.log(
                  'I4 replay verified: same key, frozen bytes, and receipt',
                );
              }
              outgoing.writeHead(reply.statusCode, reply.headers).end(response);
            });
          },
        );
        proxied.on('error', () => outgoing.writeHead(502).end());
        proxied.end(body);
      });
    },
  );
  server.listen(55456, '127.0.0.1', () =>
    console.log('I4 HTTPS fixture ready'),
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
