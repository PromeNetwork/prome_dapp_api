import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNumber, IsEnum } from 'class-validator';

export enum ServerRegion {
  europe = 'europe',
  south_asia = 'south_asia',
  america = 'america',
  southeast_asia = 'southeast_asia',
  east_asia = 'east_asia',
  middle_east_africa = 'middle_east_africa',
}

export class updateAlphaTestRecordDto {
  @ApiProperty()
  @IsString()
  uid: string;

  @ApiProperty()
  @IsNumber()
  score: number;

  @ApiProperty()
  @IsNumber()
  e4c: number;
}

export class updateAlphaTestRecordV2Dto {
  @ApiProperty()
  @IsString()
  uid: string;

  @ApiProperty()
  @IsNumber()
  score: number;

  @ApiProperty()
  @IsNumber()
  e4c: number;

  @ApiProperty()
  @IsEnum(ServerRegion)
  serverRegion: ServerRegion;
}

export class CreateE4cRecordDto {
  @ApiProperty()
  @IsString()
  avadakedavra: string;
}
