const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const { ValidationPipe } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const { AppModule } = require('../../dist/app.module');

async function main() {
  const database = new URL(process.env.DATABASE_URL);
  const tls = process.env.I2_TLS_DIR;
  if (
    database.protocol !== 'postgresql:' ||
    database.hostname !== '127.0.0.1' ||
    !database.pathname.endsWith('_test') ||
    !tls
  ) {
    throw new Error('Use a loopback test database and local TLS files');
  }

  const api = await NestFactory.create(AppModule);
  api.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      validationError: { target: false, value: false },
    }),
  );
  api.enableShutdownHooks();
  await api.listen(55444, '127.0.0.1');

  const held = new Map();
  const enabled = new Set();
  let expireCheck = false;
  let rejectRefresh = false;
  let failPreview = true;
  let failList = false;
  https
    .createServer(
      {
        key: fs.readFileSync(path.join(tls, 'localhost.key')),
        cert: fs.readFileSync(path.join(tls, 'localhost.pem')),
      },
      (req, res) => {
        if (req.method === 'POST') {
          switch (req.url) {
            case '/__i2/expire':
              expireCheck = true;
              return res.writeHead(204).end();
            case '/__i2/release-check':
              enabled.add('/mvp/checks');
              return res.writeHead(204).end();
            case '/__i2/release-coffee':
              enabled.add('/mvp/transactions');
              return res.writeHead(204).end();
            case '/__i2/fail-list':
              failList = true;
              return res.writeHead(204).end();
          }
          if (req.url === '/auth/refresh' && rejectRefresh) {
            rejectRefresh = false;
            console.log('fixture refresh rejected for expired session');
            return res.writeHead(401).end();
          }
          if (req.url === '/mvp/check-previews' && failPreview) {
            failPreview = false;
            console.log('fixture check preview unavailable');
            return res.writeHead(503).end();
          }
          if (req.url === '/mvp/checks' && expireCheck) {
            expireCheck = false;
            rejectRefresh = true;
            console.log('fixture access rejected on check recovery');
            return res.writeHead(401).end();
          }
        }
        if (
          req.method === 'GET' &&
          req.url.split('?')[0].endsWith('/checks') &&
          failList
        ) {
          failList = false;
          console.log('fixture check list unavailable');
          return res.writeHead(503).end();
        }

        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          const requestBytes = Buffer.concat(chunks);
          const upstream = http.request(
            {
              host: '127.0.0.1',
              port: 55444,
              path: req.url,
              method: req.method,
              headers: req.headers,
            },
            (reply) => {
              const replyChunks = [];
              reply.on('data', (chunk) => replyChunks.push(chunk));
              reply.on('end', () => {
                const responseBytes = Buffer.concat(replyChunks);
                if (
                  req.method === 'POST' &&
                  reply.statusCode === 201 &&
                  (req.url === '/mvp/checks' ||
                    (req.url === '/mvp/transactions' &&
                      JSON.parse(requestBytes).amountMinor === 1800))
                ) {
                  const key = req.headers['idempotency-key'];
                  const receipt = JSON.parse(responseBytes);
                  if (!held.has(req.url)) {
                    held.set(req.url, { key, body: requestBytes, receipt });
                    console.log(
                      `fixture ${req.url} committed; dropping HTTPS response`,
                    );
                  } else if (held.get(req.url).key === key) {
                    const original = held.get(req.url);
                    const sameBody = original.body.equals(requestBytes);
                    const sameReceipt = isDeepStrictEqual(
                      original.receipt,
                      receipt,
                    );
                    console.log(
                      `fixture ${req.url} replay sameKey=true sameBody=${sameBody} sameReceipt=${sameReceipt} delivered=${enabled.has(req.url)}`,
                    );
                    if (!sameBody || !sameReceipt)
                      return res.writeHead(500).end();
                  }
                  if (held.get(req.url).key === key && !enabled.has(req.url))
                    return req.socket.destroy();
                }
                res
                  .writeHead(reply.statusCode, reply.headers)
                  .end(responseBytes);
              });
            },
          );
          upstream.on('error', () => res.writeHead(502).end());
          upstream.end(requestBytes);
        });
      },
    )
    .listen(55445, '127.0.0.1', () => console.log('fixture I2 HTTPS ready'));
}

main().catch(() => {
  console.error('fixture startup failed');
  process.exitCode = 1;
});
