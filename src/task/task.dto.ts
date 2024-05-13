import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNumber, IsEnum, IsOptional } from 'class-validator';

/**
 * 'FOLLOW_TWITTER' | 'INTERACT_TWITTER'| 'LIKE_TWEETER' | 'JOIN_TELEGRAM' | 'LOGIN_WALLET' | 'VERIFY_EMAIL' | 'QUESTION'|'SHARE'
 */
export enum TaskType {
  FOLLOW_TWITTER = 'FOLLOW_TWITTER',
  INTERACT_TWITTER = 'INTERACT_TWITTER',
  LIKE_TWEETER = 'LIKE_TWEETER',
  JOIN_TELEGRAM = 'JOIN_TELEGRAM',
  LOGIN_WALLET = 'LOGIN_WALLET',
  VERIFY_EMAIL = 'VERIFY_EMAIL',
  QUESTION = 'QUESTION',
  SHARE = 'SHARE',
}
export class Task {
  @ApiProperty()
  @IsNumber()
  @IsOptional()
  id?: number;
  @ApiProperty()
  @IsEnum(TaskType)
  type: TaskType;
  @ApiProperty()
  @IsString()
  status: 'complete' | 'incomplete' | 'pending';
  @ApiProperty()
  @IsString()
  address: string;
  @ApiProperty()
  @IsString()
  @IsOptional()
  content?: string;
}
