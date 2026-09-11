import { Injectable } from '@nestjs/common';
import { createCipheriv, randomBytes } from 'crypto';
import { AuthConfig } from './auth.config';

const VERSION = 'v1';

@Injectable()
export class AppleRefreshTokenCipherService {
  private encryptionKey?: Buffer;

  constructor(private readonly config: AuthConfig) {}

  assertConfigured(): void {
    void this.key();
  }

  encrypt(refreshToken: string, authIdentityId: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key(), iv);
    cipher.setAAD(
      Buffer.from(`apple-refresh-token:${VERSION}:${authIdentityId}`, 'utf8'),
    );
    const ciphertext = Buffer.concat([
      cipher.update(refreshToken, 'utf8'),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    return [VERSION, iv, ciphertext, tag]
      .map((part) =>
        typeof part === 'string' ? part : part.toString('base64url'),
      )
      .join('.');
  }

  private key(): Buffer {
    this.encryptionKey ??= this.config.appleRefreshTokenEncryptionKey;
    return this.encryptionKey;
  }
}
