import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { AlphaTestService } from './alphaTest.service';
import { AlphaTestController } from './alphaTest.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [ConfigModule, AuthModule],
  providers: [
    AlphaTestService,
    {
      provide: Pool,
      inject: [ConfigService],
      useFactory(configService: ConfigService) {
        return new Pool({
          connectionString: configService.getOrThrow('PG'),
          ssl: {
            rejectUnauthorized: false,
          },
        });
      },
    },
  ],
  exports: [AlphaTestService],
  controllers: [AlphaTestController],
})
export class AlphaTestModule {}
