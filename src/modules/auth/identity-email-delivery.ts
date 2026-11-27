import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { constants } from 'fs';
import { lstat, writeFile } from 'fs/promises';
import { isAbsolute, join } from 'path';

export type EmailPurpose = 'verify' | 'recover' | 'add_password';
const subjects: Record<EmailPurpose, string> = {
  verify: 'Verificação de e-mail / Email verification',
  recover: 'Recuperação de senha / Password recovery',
  add_password: 'Vincular e-mail e senha / Link email and password',
};

@Injectable()
export class IdentityEmailDelivery {
  assertAvailable(): void {
    this.configuration();
  }

  async deliver(
    email: string,
    purpose: EmailPurpose,
    code: string,
  ): Promise<void> {
    const config = this.configuration();
    try {
      if (config.mode === 'local') {
        const status = await lstat(config.directory);
        if (
          !status.isDirectory() ||
          (status.mode & 0o077) !== 0 ||
          status.uid !== process.getuid?.()
        )
          throw new Error();
        await writeFile(
          join(config.directory, `${randomUUID()}.json`),
          JSON.stringify({
            provider: 'resend-simulated',
            email,
            purpose,
            code,
          }),
          {
            flag:
              constants.O_CREAT |
              constants.O_EXCL |
              constants.O_WRONLY |
              constants.O_NOFOLLOW,
            mode: 0o600,
          },
        );
        return;
      }
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(5_000),
        headers: {
          Authorization: `Bearer ${config.key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: config.from,
          to: [email],
          subject: `Lenver · ${subjects[purpose]}`,
          text: `Seu código Lenver é ${code}. Ele expira em 15 minutos.\nYour Lenver code is ${code}. It expires in 15 minutes.`,
        }),
      });
      await response.body?.cancel();
      if (!response.ok) throw new Error();
    } catch {
      throw new ServiceUnavailableException('Email delivery unavailable');
    }
  }

  private configuration() {
    const directory = process.env.LENVER_LOCAL_EMAIL_MAILBOX;
    if (directory) {
      if (isAbsolute(directory) && process.env.NODE_ENV !== 'production') {
        return { mode: 'local' as const, directory };
      }
    } else {
      const key = process.env.RESEND_API_KEY;
      const from = process.env.LENVER_IDENTITY_MAIL_FROM;
      if (key && from) return { mode: 'resend' as const, key, from };
    }
    throw new ServiceUnavailableException('Email delivery unavailable');
  }
}
