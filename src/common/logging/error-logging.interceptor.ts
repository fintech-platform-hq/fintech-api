import {
  CallHandler,
  ExecutionContext,
  HttpException,
  Injectable,
  Logger,
  NestInterceptor,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Request } from 'express';
import { Observable, catchError, throwError } from 'rxjs';

type RequestWithId = Request & { requestId?: string };

@Injectable()
export class ErrorLoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ErrorLoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    return next.handle().pipe(
      catchError((error: unknown) => {
        const request = context.switchToHttp().getRequest<RequestWithId>();
        const route = request.route as { path?: unknown } | undefined;
        const path = typeof route?.path === 'string' ? route.path : '';
        const auth = /^\/(v1\/)?auth\//i.test(path);
        if (auth || path.startsWith('/mvp/')) {
          const responseError =
            error instanceof HttpException
              ? error
              : new ServiceUnavailableException(
                  auth
                    ? 'Authentication temporarily unavailable'
                    : 'Financial account temporarily unavailable',
                );
          this.logger.error({
            requestId: request.requestId,
            path,
            statusCode: responseError.getStatus(),
          });
          return throwError(() => responseError);
        }
        const loggedError: Record<string, string | undefined> = {
          requestId: request.requestId,
          message: error instanceof Error ? error.message : String(error),
        };

        if (process.env.NODE_ENV === 'development' && error instanceof Error) {
          loggedError.stack = error.stack;
        }

        this.logger.error(loggedError);

        return throwError(() => error);
      }),
    );
  }
}
