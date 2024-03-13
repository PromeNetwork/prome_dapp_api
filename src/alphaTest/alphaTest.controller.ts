import { Controller, Get, Post, Put, Body, Query } from '@nestjs/common';
import { AlphaTestService } from './alphaTest.service';
import {
  updateAlphaTestRecordDto,
  updateAlphaTestRecordV2Dto,
  ServerRegion,
} from './alphaTest.dto';

@Controller('alphaTest')
export class AlphaTestController {
  constructor(private readonly alphaTestService: AlphaTestService) {}

  @Get('')
  async readAlphaTestRecord(@Query('uid') uid: string) {
    return this.alphaTestService.readAlphaTestRecord(uid);
  }

  // @Post('')
  // async createAlphaTestRecord(
  //   @Body() { uid, score, e4c }: updateAlphaTestRecordDto,
  // ) {
  //   return this.alphaTestService.updateAlphaTestRecord(uid, score, e4c);
  // }

  // @Put('')
  // async updateAlphaTestRecord(
  //   @Body() { uid, score, e4c }: updateAlphaTestRecordDto,
  // ) {
  //   return this.alphaTestService.updateAlphaTestRecord(uid, score, e4c);
  // }

  @Get('v2')
  async readAlphaTestRecordV2(
    @Query('uid') uid: string,
    @Query('serverRegion') serverRegion: ServerRegion | string,
  ) {
    return this.alphaTestService.readAlphaTestRecordV2(uid, serverRegion);
  }

  // @Post('v2')
  // async createAlphaTestRecordV2(
  //   @Body() { uid, score, e4c, serverRegion }: updateAlphaTestRecordV2Dto,
  // ) {
  //   return this.alphaTestService.updateAlphaTestRecordV2(
  //     uid,
  //     score,
  //     e4c,
  //     serverRegion,
  //   );
  // }

  // @Put('v2')
  // async updateAlphaTestRecordV2(
  //   @Body() { uid, score, e4c, serverRegion }: updateAlphaTestRecordV2Dto,
  // ) {
  //   return this.alphaTestService.updateAlphaTestRecordV2(
  //     uid,
  //     score,
  //     e4c,
  //     serverRegion,
  //   );
  // }

  @Get('holderE4c')
  async readE4cAmountForPaymintHolder(@Query('address') address: string) {
    return this.alphaTestService.readE4cAmountForPaymintHolder(
      address.toLowerCase(),
    );
  }

  @Get('SBT')
  async checkIfAddressHaveSBT(@Query('address') address: string) {
    return this.alphaTestService.checkIfAddressHaveSBT(address.toLowerCase());
  }
}
