import {
  HttpException,
  HttpStatus,
  Injectable,
  NestMiddleware,
} from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

interface Counter {
  count: number;
  resetAt: number;
}

const WINDOW_MS = 15 * 60 * 1000;
const LIMITS: Record<string, number> = {
  '/auth/register': 5,
  '/auth/login': 5,
  '/auth/apple': 5,
  '/auth/apple/link': 5,
  '/auth/refresh': 10,
  '/auth/logout': 30,
  '/auth/verification': 5,
  '/auth/verification/confirm': 10,
  '/auth/recovery': 5,
  '/auth/recovery/confirm': 10,
  '/auth/apple/unlink': 5,
  '/auth/verification/email': 5,
  '/auth/password/link': 5,
  '/auth/password/link/confirm': 10,
  '/auth/password/unlink': 5,
  '/auth/password/change/proof': 5,
  '/auth/password/change': 5,
};

@Injectable()
export class AuthRateLimitMiddleware implements NestMiddleware {
  // ponytail: process-local storage is valid only while deployment is single-instance; replace with shared storage before scale-out.
  private readonly counters = new Map<string, Counter>();

  use(request: Request, response: Response, next: NextFunction): void {
    response.setHeader('Cache-Control', 'no-store');
    const bucketPath =
      request.path
        .toLowerCase()
        .replace(/^\/v1(?=\/auth\/)/, '')
        .replace(/\/+$/, '') || '/';
    const limit = LIMITS[bucketPath];
    if (!limit) {
      next();
      return;
    }

    const now = Date.now();
    const key = `${request.ip}:${bucketPath}`;
    const current = this.counters.get(key);
    const counter =
      !current || current.resetAt <= now
        ? { count: 0, resetAt: now + WINDOW_MS }
        : current;

    counter.count += 1;
    this.counters.set(key, counter);
    if (this.counters.size > 10_000) {
      for (const [storedKey, stored] of this.counters) {
        if (stored.resetAt <= now) this.counters.delete(storedKey);
      }
      if (this.counters.size > 10_000) {
        const oldestKey = this.counters.keys().next().value as
          string | undefined;
        if (oldestKey) this.counters.delete(oldestKey);
      }
    }
    response.setHeader(
      'X-RateLimit-Remaining',
      String(Math.max(0, limit - counter.count)),
    );

    if (counter.count > limit) {
      response.setHeader(
        'Retry-After',
        String(Math.ceil((counter.resetAt - now) / 1000)),
      );
      throw new HttpException(
        'Too many authentication requests',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    next();
  }
}
