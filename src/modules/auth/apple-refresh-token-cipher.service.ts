import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
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

  decrypt(envelope: string, authIdentityId: string): string {
    const segments = envelope.split('.');
    if (segments.length !== 4) throw invalidEnvelope();
    const [version, encodedIv, encodedCiphertext, encodedTag] = segments;
    if (version !== VERSION || !encodedIv || !encodedCiphertext || !encodedTag)
      throw invalidEnvelope();
    try {
      const iv = Buffer.from(encodedIv, 'base64url');
      const ciphertext = Buffer.from(encodedCiphertext, 'base64url');
      const tag = Buffer.from(encodedTag, 'base64url');
      if (
        iv.toString('base64url') !== encodedIv ||
        ciphertext.toString('base64url') !== encodedCiphertext ||
        tag.toString('base64url') !== encodedTag
      )
        throw invalidEnvelope();
      if (iv.length !== 12 || tag.length !== 16 || ciphertext.length === 0)
        throw invalidEnvelope();
      const decipher = createDecipheriv('aes-256-gcm', this.key(), iv);
      decipher.setAAD(
        Buffer.from(`apple-refresh-token:${VERSION}:${authIdentityId}`, 'utf8'),
      );
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]).toString('utf8');
      if (!plaintext) throw invalidEnvelope();
      return plaintext;
    } catch {
      throw invalidEnvelope();
    }
  }

  private key(): Buffer {
    this.encryptionKey ??= this.config.appleRefreshTokenEncryptionKey;
    return this.encryptionKey;
  }
}

function invalidEnvelope(): Error {
  return new Error('Invalid Apple refresh token envelope');
}
