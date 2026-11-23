import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { NextFunction, Request, Response } from 'express';

type RequestWithId = Request & { requestId?: string };

@Injectable()
export class RequestLoggingMiddleware implements NestMiddleware {
  private readonly logger = new Logger(RequestLoggingMiddleware.name);

  use(request: RequestWithId, response: Response, next: NextFunction): void {
    const requestId = randomUUID();
    const startedAt = process.hrtime.bigint();

    request.requestId = requestId;
    response.setHeader('X-Request-Id', requestId);

    response.on('finish', () => {
      const responseTime =
        Number(process.hrtime.bigint() - startedAt) / 1_000_000;

      const route = request.route as { path?: unknown } | undefined;
      this.logger.log({
        requestId,
        method: request.method,
        path: typeof route?.path === 'string' ? route.path : undefined,
        statusCode: response.statusCode,
        responseTimeMs: Math.round(responseTime * 100) / 100,
      });
    });

    next();
  }
}
