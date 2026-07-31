import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getServiceStatus() {
    return {
      name: 'fintech-api',
      status: 'running',
    };
  }

  @Get('health')
  getHealth() {
    return {
      status: 'ok',
    };
  }
}
