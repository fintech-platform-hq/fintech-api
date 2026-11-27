import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { DatabaseService } from './common/database/database.service';
import { COMPATIBILITY_SCHEMA_VERSION } from './common/database/schema-compatibility';

const READINESS_QUERY_TIMEOUT_MILLISECONDS = 1_500;

@Controller()
export class AppController {
  constructor(private readonly database: DatabaseService) {}

  @Get()
  getServiceStatus() {
    return {
      name: 'lenver-api',
      status: 'running',
    };
  }

  @Get('health')
  getHealth() {
    return {
      status: 'ok',
    };
  }

  @Get('ready')
  async getReadiness() {
    try {
      const result = await this.database.queryWithTimeout<{ version: string }>(
        'SELECT version FROM lenver_schema_version WHERE singleton = true',
        READINESS_QUERY_TIMEOUT_MILLISECONDS,
      );

      if (result.rows[0]?.version === COMPATIBILITY_SCHEMA_VERSION) {
        return { status: 'ready' };
      }
    } catch {
      // Keep database and schema details out of the public readiness response.
    }

    throw new ServiceUnavailableException({ status: 'not_ready' });
  }
}
