const { readFileSync } = require('node:fs');
const { request } = require('node:http');
const { createServer } = require('node:https');
const { join } = require('node:path');
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { ValidationPipe } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('../../dist/app.module');

const upstream = 'http://127.0.0.1:55464';
const password = 'fictional i5 password';

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
  const referenceAt = '2026-11-18T11:00:00Z';
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
  await expense(5500, '2026-11-14T12:00:00Z', 'Despesa anterior', '1');
  const check = await post(
    '/mvp/checks',
    { accountId, observedMinor: '80000', referenceAt, expectedRevision: '2' },
    accessToken,
  );
  await expense(1800, '2026-11-18T12:10:00Z', 'Café depois do corte', '3');
}

async function main() {
  const db = new URL(process.env.DATABASE_URL);
  const tls = process.env.I5_TLS_DIR;
  if (
    db.protocol !== 'postgresql:' ||
    db.hostname !== '127.0.0.1' ||
    !db.pathname.endsWith('_test') ||
    !tls
  ) {
    throw new Error('Use a loopback test database and local TLS files');
  }

  const app = await NestFactory.create(AppModule);
  app.set('trust proxy', 1);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      validationError: { target: false, value: false },
      transform: true,
    }),
  );
  app.enableShutdownHooks();
  await app.listen(55464, '127.0.0.1');
  if (process.env.I5_SEED === '1') {
    await seed('i5-a@example.test');
    await post('/auth/register', { email: 'i5-b@example.test', password });
    await seed('i5-c@example.test');
    await post('/auth/register', { email: 'i5-d@example.test', password });
  }

  let interrupted;
  let release = false;
  let replayed = false;
  let attempts = 0;
  const server = createServer(
    {
      key: readFileSync(join(tls, 'localhost.key')),
      cert: readFileSync(join(tls, 'localhost.pem')),
    },
    (incoming, outgoing) => {
      if (incoming.method === 'POST' && incoming.url === '/__i5/release') {
        release = true;
        return outgoing.writeHead(204).end();
      }
      if (incoming.method === 'GET' && incoming.url === '/__i5/replay') {
        return outgoing
          .writeHead(200)
          .end(replayed ? 'verified' : interrupted ? 'interrupted' : 'pending');
      }
      if (incoming.method === 'GET' && incoming.url === '/__i5/attempts') {
        return outgoing.writeHead(200).end(String(attempts));
      }
      const chunks = [];
      incoming.on('data', (chunk) => chunks.push(chunk));
      incoming.on('end', () => {
        const body = Buffer.concat(chunks);
        const headers = { ...incoming.headers };
        delete headers['x-forwarded-for'];
        let intercepted = false;
        if (
          incoming.method === 'POST' &&
          ['/auth/login', '/mvp/audited-changes'].includes(incoming.url)
        ) {
          try {
            const payload = JSON.parse(body);
            if (incoming.url === '/auth/login') {
              // Keep concurrent simulator lanes independent under production-style throttling.
              const actor = /^i5-([a-d])@example\.test$/.exec(payload.email);
              if (actor)
                headers['x-forwarded-for'] =
                  '192.0.2.' + (1 + actor[1].charCodeAt(0) - 97);
            } else {
              intercepted = payload.action === 'correct_base';
              if (intercepted) attempts++;
            }
          } catch {
            // The API validates malformed requests.
          }
        }
        const proxied = request(
          upstream + incoming.url,
          {
            method: incoming.method,
            headers,
          },
          (reply) => {
            const parts = [];
            reply.on('data', (part) => parts.push(part));
            reply.on('end', () => {
              const response = Buffer.concat(parts);
              if (intercepted && reply.statusCode === 201) {
                const key = incoming.headers['idempotency-key'];
                const receipt = JSON.parse(response);
                if (!interrupted) {
                  interrupted = { key, body, receipt };
                  console.log(
                    'I5 correction committed; HTTPS response intentionally dropped',
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
                  'I5 replay verified: same key, frozen bytes, and receipt',
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
  server.listen(55465, '127.0.0.1', () =>
    console.log('I5 HTTPS fixture ready'),
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
