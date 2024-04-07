import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import RepeatSubmitInterceptor from './interceptors/RepeatSubmitInterceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
    }),
  );
  app.useGlobalInterceptors(new RepeatSubmitInterceptor());

  const configService = app.get(ConfigService);

  if (Boolean(+configService.get<string>('SWAGGER_ENABLED', '0'))) {
    const config = new DocumentBuilder()
      // .addServer('/v2-testing')
      .setTitle('Account System V2')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, config);

    SwaggerModule.setup('api', app, document);
  }

  await app.listen(Number(configService.get<string>('PORT', '3000')));
}
bootstrap();
