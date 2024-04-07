import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { TaskService } from './task.service';
import { TaskController } from './task.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [ConfigModule, AuthModule],
  providers: [
    TaskService,
    {
      provide: Pool,
      inject: [ConfigService],
      useFactory(configService: ConfigService) {
        return new Pool({ connectionString: configService.getOrThrow('PG') });
      },
    },
  ],
  exports: [TaskService],
  controllers: [TaskController],
})
export class TaskModule {}
