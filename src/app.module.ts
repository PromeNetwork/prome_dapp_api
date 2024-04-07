import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppController } from './app.controller';
import { AccountModule } from './account/account.module';
import { TaskModule } from './task/task.module';
import { AlphaTestModule } from './alphaTest/alphaTest.module';
import { E4cModule } from './e4c/e4c.module';

@Module({
  imports: [
    ConfigModule.forRoot(),
    CacheModule.register({
      imports: [ConfigModule],
      inject: [ConfigService],
      isGlobal: true,
    }),
    AccountModule,
    AlphaTestModule,
    E4cModule,
    TaskModule,
  ],
  controllers: [AppController],
})
export class AppModule {}
