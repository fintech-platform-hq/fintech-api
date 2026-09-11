export type AuthMethod = 'password' | 'apple';

export interface AuthPrincipal {
  userId: string;
  authMethod?: AuthMethod;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: 900;
}
