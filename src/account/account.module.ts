import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { AccountService } from './account.service';
import { AccountController } from './account.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [ConfigModule, AuthModule],
  providers: [
    AccountService,
    {
      provide: Pool,
      inject: [ConfigService],
      useFactory(configService: ConfigService) {
        return new Pool({ connectionString: configService.getOrThrow('PG') });
      },
    },
  ],
  exports: [AccountService],
  controllers: [AccountController],
})
export class AccountModule {}
