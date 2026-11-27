import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  const localEmail = process.env.LENVER_LOCAL_EMAIL_MAILBOX !== undefined;
  if (localEmail && process.env.NODE_ENV === 'production') {
    throw new Error('A local email mailbox requires a non-production runtime');
  }
  app.set('trust proxy', localEmail ? false : 1);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      validationError: {
        target: false,
        value: false,
      },
    }),
  );

  app.enableShutdownHooks();

  const port = Number(process.env.PORT) || 3000;
  await app.listen(port, localEmail ? '127.0.0.1' : '0.0.0.0');
}

void bootstrap();
