import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { E4cService } from './e4c.service';
import { E4cController } from './e4c.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [ConfigModule, AuthModule],
  providers: [
    E4cService,
    {
      provide: Pool,
      inject: [ConfigService],
      useFactory(configService: ConfigService) {
        return new Pool({ connectionString: configService.getOrThrow('PG') });
      },
    },
  ],
  exports: [E4cService],
  controllers: [E4cController],
})
export class E4cModule {}
