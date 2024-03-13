import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsBoolean,
  IsObject,
  IsOptional,
  IsEnum,
  IsNotEmpty,
  ValidateNested,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';

export class SendVerificationCodeDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;
}

export class SendVerificationCodeforSignatureDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  address: string;
}

export class SendVerificationCodeforResetPasswordDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;
}

export class sendVerificationCodeforUpdateEmailDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Transform((param) => param.value.toLowerCase())
  oldEmail: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Transform((param) => param.value.toLowerCase())
  newEmail: string;
}

export class VerifyVerificationCodeDto {
  @ApiProperty()
  @IsString()
  code: string;

  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;
}

export class RegisterViaEmailDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  username: string;

  @ApiProperty()
  @IsString()
  hash1: string;

  @ApiProperty()
  @IsBoolean()
  newsLetterSubscription: boolean;
}

export class GameRegisterViaEmailDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  code: string;

  @ApiProperty()
  @IsString()
  hash1: string;

  @ApiProperty()
  @IsString()
  @IsOptional()
  referralId?: string;
}

export class RegisterViaGoogleDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  username: string;

  @ApiProperty()
  @IsString()
  hash1: string;

  @ApiProperty()
  @IsBoolean()
  newsLetterSubscription: boolean;

  @ApiProperty()
  @IsString()
  @IsOptional()
  referralId?: string;
}

export class RegisterViaFacebookDto {
  @ApiProperty()
  @IsString()
  userID: string;

  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  username: string;

  @ApiProperty()
  @IsString()
  hash1: string;

  @ApiProperty()
  @IsBoolean()
  newsLetterSubscription: boolean;

  @ApiProperty()
  @IsString()
  @IsOptional()
  referralId?: string;
}

export class RevokeFacebookFacebookDto {
  @ApiProperty()
  @IsString()
  userID: string;
}

export class LoginViaEmailDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  hash1: string;
}

export class LoginViaEmailV1Dto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  hash1: string;

  @ApiProperty()
  @IsString()
  password: string;
}

export class LoginViaGoogleDto {
  @ApiProperty()
  @IsString()
  email: string;

  @ApiProperty()
  @IsString()
  hash1: string;
}

export class LoginViaFacebookDto {
  @ApiProperty()
  @IsString()
  userID: string;

  @ApiProperty()
  @IsString()
  hash1: string;
}

export class LoginViaMetamaskDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  address: string;

  @ApiProperty()
  @IsString()
  signature: string;
}

export class RegisterViaMetamaskDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  address: string;

  @ApiProperty()
  @IsString()
  signature: string;
}

export class UpdateBlockusSuiWalletDto {
  @ApiProperty()
  @IsString()
  uid: string;

  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  address: string;
}

export class LogActionDto {
  @ApiProperty()
  @IsString()
  action: string;

  @ApiProperty()
  @IsObject()
  data: any;
}

export enum WalletType {
  Particle = 'Particle',
  MetaMask = 'MetaMask',
}

export enum WalletChain {
  Ethereum = 'Ethereum',
  EthereumGoerli = 'EthereumGoerli',
  Sui = 'Sui',
  Tezos = 'Tezos',
}

export class Wallet {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  address: string;

  @ApiProperty()
  @IsEnum(WalletChain)
  chain: WalletChain;

  @ApiProperty()
  @IsEnum(WalletType)
  type: WalletType;
}

export class ReplaceWalletDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsObject()
  @ValidateNested({ each: true })
  @Type(() => Wallet)
  wallet: Wallet;
}

export class UpdateWalletDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsObject()
  @ValidateNested({ each: true })
  @Type(() => Wallet)
  wallet: Wallet;
}

export class SwitchMetamaskWalletDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsObject()
  @ValidateNested({ each: true })
  @Type(() => Wallet)
  wallet: Wallet;
}

export class UpdateAvatarDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  avatar: string;
}

export class UpdateUsernameDto {
  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  username: string;
}

export class UpdateEmailDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  code: string;
}

export class UpdateBasicInfoDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Transform((param) => param.value.toLowerCase())
  oldEmail: string;

  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  newEmail: string;

  @ApiProperty()
  @IsString()
  username: string;
}

export class UpdateGoogleSocialAccountDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Transform((param) => param.value.toLowerCase())
  email: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  googleAccount: string;
}

export class DeleteGoogleSocialAccountDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @Transform((param) => param.value.toLowerCase())
  email: string;
}

export class ResetPasswordDto {
  @ApiProperty()
  @IsString()
  newPassword: string;

  @ApiProperty()
  @IsString()
  code: string;
}

export class ChangePasswordDto {
  @ApiProperty()
  @IsString()
  oldPassword: string;

  @ApiProperty()
  @IsString()
  newPassword: string;

  @ApiProperty()
  @IsString()
  @Transform((param) => param.value.toLowerCase())
  email: string;
}

export enum usernameAvailability {
  LengthNotMatch = 'LengthNotMatch',
  AlreadyUsed = 'AlreadyUsed',
  HasIllegalCharacter = 'HasIllegalCharacter',
  ContainSensitiveWord = 'ContainSensitiveWord',
  UsernameAvailable = 'UsernameAvailable',
}

export enum emailAvailability {
  AlreadyUsed = 'AlreadyUsed',
  Illegalformat = 'Illegalformat',
  EmailAvailable = 'EmailAvailable',
}

export enum loginStatus {
  LoginSuccessfully = 'LoginSuccessfully',
  EmailUnverified = 'EmailUnverified',
  WrongPassword = 'WrongPassword',
  UserNotFound = 'UserNotFound',
}

export enum registerSatatus {
  EmailUnavailable = 'EmailUnavailable',
  PasswordFlavorMismatch = 'PasswordFlavorMismatch',
  WalletAlreadyUsed = 'WalletAlreadyUsed',
}

export enum accountStatus {
  OldAccount = 'OldAccount',
  NewAccount = 'NewAccount',
  Unregistered = 'Unregistered',
}
