import { Controller, Get, Post, Body, Query } from '@nestjs/common';
import { E4cService } from './e4c.service';
import { CreateE4cRecordDto } from './e4c.dto';

@Controller('e4c')
export class E4cController {
  constructor(private readonly e4cService: E4cService) {}

  @Get('record')
  async readE4cAridropRecord(@Query('address') address: string) {
    return this.e4cService.readE4cAridropRecord(address.toLowerCase());
  }

  @Get('event')
  async readE4cAridropEvent() {
    return this.e4cService.readE4cAridropEvent();
  }

  @Get('v2/record')
  async readE4cHitoricalRecord(@Query('uid') uid: string) {
    return this.e4cService.readE4cHitoricalRecord(uid);
  }

  @Post('v2/record')
  async createE4cRecord(@Body() { avadakedavra }: CreateE4cRecordDto) {
    return this.e4cService.createE4cRecord(avadakedavra);
  }

  @Get('v2/tx')
  async readE4cTx(@Query('txid') txid: string) {
    return this.e4cService.readE4cTx(txid);
  }

  @Get('v2/balance')
  async readE4cBalance(@Query('uid') uid: string) {
    return this.e4cService.readE4cBalance(uid);
  }
}
