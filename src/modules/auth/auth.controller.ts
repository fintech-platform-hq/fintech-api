import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthResponse } from './auth.types';
import { AuthGuard } from './auth.guard';
import type { AuthenticatedRequest } from './auth.guard';
import { CredentialsDto } from './dto/credentials.dto';
import { AppleAuthenticationDto } from './dto/apple-authentication.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: CredentialsDto): Promise<AuthResponse> {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: CredentialsDto): Promise<AuthResponse> {
    return this.authService.login(dto);
  }

  @Post('apple')
  @HttpCode(HttpStatus.OK)
  apple(@Body() dto: AppleAuthenticationDto): Promise<AuthResponse> {
    return this.authService.apple(dto);
  }

  @Post('apple/link')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  linkApple(
    @Body() dto: AppleAuthenticationDto,
    @Req() request: AuthenticatedRequest,
  ): Promise<void> {
    return this.authService.linkApple(request.principal, dto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() dto: RefreshTokenDto): Promise<AuthResponse> {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Body() dto: RefreshTokenDto): Promise<void> {
    await this.authService.logout(dto.refreshToken);
  }
}
