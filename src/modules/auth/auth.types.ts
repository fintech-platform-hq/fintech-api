export type AuthMethod = 'password' | 'apple';

export interface AuthPrincipal {
  userId: string;
  authMethod?: AuthMethod;
  familyId?: string;
  expiresAt?: number;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: 900;
}
