const { readFileSync } = require('node:fs');
const { request } = require('node:http');
const { createServer } = require('node:https');
const { join } = require('node:path');
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { ValidationPipe } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('../../dist/app.module');

const upstream = 'http://127.0.0.1:55446';
const password = 'fictional i3 password';

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

async function seed() {
  const a = await post('/auth/register', {
    email: 'i3-a@example.test',
    password,
  });
  await post('/auth/register', { email: 'i3-b@example.test', password });
  const { account } = await post(
    '/mvp/account',
    {
      coverageStart: '2026-11-14T12:00:00Z',
      baseMinor: '90000',
      referenceZone: 'America/Sao_Paulo',
    },
    a.accessToken,
  );
  function expense(amountMinor, occurredAt, description, expectedRevision) {
    return post(
      '/mvp/transactions',
      {
        accountId: account.id,
        amountMinor,
        occurredAt,
        description,
        type: 'expense',
        currency: 'BRL',
        expectedRevision,
        clientMutationId: randomUUID(),
      },
      a.accessToken,
    );
  }
  await expense(5500, '2026-11-18T10:00:00Z', 'Despesa anterior', '1');
  await post(
    '/mvp/checks',
    {
      accountId: account.id,
      observedMinor: '80000',
      referenceAt: '2026-11-18T12:00:00Z',
      expectedRevision: '2',
    },
    a.accessToken,
  );
  await expense(1800, '2026-11-18T12:10:00Z', 'Café depois do corte', '3');
}

async function main() {
  const db = new URL(process.env.DATABASE_URL);
  const tls = process.env.I3_TLS_DIR;
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
      validationError: { target: false, value: false },
    }),
  );
  app.enableShutdownHooks();
  await app.listen(55446, '127.0.0.1');
  if (process.env.I3_SEED === '1') await seed();

  let held;
  let release = false;
  let failPreview = true;
  let requests = 0;
  const server = createServer(
    {
      key: readFileSync(join(tls, 'localhost.key')),
      cert: readFileSync(join(tls, 'localhost.pem')),
    },
    (incoming, outgoing) => {
      if (incoming.method === 'POST' && incoming.url === '/__i3/release') {
        release = true;
        return outgoing.writeHead(204).end();
      }
      if (incoming.method === 'GET' && incoming.url === '/__i3/count') {
        return outgoing
          .writeHead(200, { 'Content-Type': 'text/plain' })
          .end(String(requests));
      }
      if (
        incoming.method === 'POST' &&
        incoming.url === '/mvp/recovery-previews' &&
        failPreview
      ) {
        failPreview = false;
        console.log('fixture recovery preview unavailable');
        return outgoing.writeHead(503).end();
      }

      const chunks = [];
      incoming.on('data', (chunk) => chunks.push(chunk));
      incoming.on('end', () => {
        const body = Buffer.concat(chunks);
        const recovery =
          incoming.method === 'POST' && incoming.url === '/mvp/recoveries';
        if (recovery) requests += 1;
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
                recovery &&
                reply.statusCode === 201 &&
                JSON.parse(body).action === 'create'
              ) {
                const key = incoming.headers['idempotency-key'];
                const receipt = JSON.parse(response);
                if (!held) {
                  held = { key, body, receipt };
                  console.log(
                    'fixture expense committed; dropping HTTPS response',
                  );
                } else if (held.key === key) {
                  const sameBody = held.body.equals(body);
                  const sameReceipt = isDeepStrictEqual(held.receipt, receipt);
                  console.log(
                    `fixture replay sameKey=true sameBody=${sameBody} sameReceipt=${sameReceipt} delivered=${release}`,
                  );
                  if (!sameBody || !sameReceipt)
                    return outgoing.writeHead(500).end();
                }
                if (key === held.key && !release)
                  return incoming.socket.destroy();
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
  server.listen(55448, '127.0.0.1', () =>
    console.log('fixture I3 HTTPS ready'),
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
  process.kill(process.pid, 'SIGTERM');
});
