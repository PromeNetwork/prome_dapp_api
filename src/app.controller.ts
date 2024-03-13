import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse } from '@nestjs/swagger';

@Controller()
export class AppController {
  @Get()
  @ApiOkResponse({ description: 'Server ok' })
  getHello(): string {
    return 'yeeee';
  }
}
