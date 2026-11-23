const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const root = path.resolve(__dirname, '../..');
const { NestFactory } = require(root + '/node_modules/@nestjs/core');
const { ValidationPipe } = require(root + '/node_modules/@nestjs/common');
const { AppModule } = require(root + '/dist/app.module');

async function main() {
  const database = new URL(process.env.DATABASE_URL);
  if (
    database.protocol !== 'postgresql:' ||
    database.hostname !== '127.0.0.1' ||
    !database.pathname.endsWith('_test') ||
    !process.env.I1B_TLS_DIR
  ) {
    throw new Error(
      'The HTTPS fixture requires a loopback test database and local TLS files',
    );
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
  await api.listen(55442, '127.0.0.1');

  let initialRegistration = false;
  let held;
  let resume = false;
  https
    .createServer(
      {
        key: fs.readFileSync(
          path.join(process.env.I1B_TLS_DIR, 'localhost.key'),
        ),
        cert: fs.readFileSync(
          path.join(process.env.I1B_TLS_DIR, 'localhost.pem'),
        ),
      },
      (req, res) => {
        if (req.method === 'POST' && req.url === '/__i1b/resume') {
          if (!held) {
            res.writeHead(409).end();
            return;
          }
          resume = true;
          res.writeHead(204).end();
          return;
        }
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => {
          const requestBytes = Buffer.concat(chunks);
          const upstream = http.request(
            {
              hostname: '127.0.0.1',
              port: 55442,
              path: req.url,
              method: req.method,
              headers: req.headers,
            },
            (reply) => {
              const responseChunks = [];
              reply.on('data', (chunk) => responseChunks.push(chunk));
              reply.on('end', () => {
                const responseBytes = Buffer.concat(responseChunks);
                const key = req.headers['idempotency-key'];
                if (
                  req.method === 'POST' &&
                  req.url === '/mvp/transactions' &&
                  reply.statusCode === 201
                ) {
                  // Suppress delivery only after Nest has returned 201 from a committed write.
                  if (!initialRegistration) {
                    initialRegistration = true;
                    console.log('fixture initial write confirmed by API');
                  } else if (!held) {
                    held = {
                      key,
                      requestBytes,
                      response: JSON.parse(responseBytes.toString()),
                    };
                    console.log(
                      'fixture second write committed; discarding response on TLS connection',
                    );
                  } else if (held.key === key) {
                    const sameBody = held.requestBytes.equals(requestBytes);
                    const sameReceipt = isDeepStrictEqual(
                      held.response,
                      JSON.parse(responseBytes.toString()),
                    );
                    console.log(
                      `fixture replay sameKey=true sameBody=${sameBody} sameReceipt=${sameReceipt} delivered=${resume}`,
                    );
                    if (!sameBody || !sameReceipt) {
                      res.writeHead(500).end();
                      return;
                    }
                  }
                  if (held?.key === key && !resume) {
                    req.socket.destroy();
                    return;
                  }
                }
                res.writeHead(reply.statusCode, reply.headers);
                res.end(responseBytes);
              });
            },
          );
          upstream.on('error', () => res.writeHead(502).end());
          upstream.end(requestBytes);
        });
      },
    )
    .listen(55443, '127.0.0.1', () => console.log('fixture HTTPS ready'));
}
main().catch(() => {
  console.error('fixture startup failed');
  process.exitCode = 1;
});
