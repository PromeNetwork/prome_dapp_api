import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { AccountService } from './account.service';
import { BlockusService } from './blockus.service';
import { AccountController } from './account.controller';
import { AuthModule } from '../auth/auth.module';
import { TaskService } from '../task/task.service';

@Module({
  imports: [ConfigModule, AuthModule],
  providers: [
    AccountService,
    BlockusService,
    TaskService,
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
  exports: [AccountService, BlockusService, TaskService],
  controllers: [AccountController],
})
export class AccountModule {}
