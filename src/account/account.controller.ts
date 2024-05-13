import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Query,
  Body,
  Request,
  UseGuards,
  Param,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt.guard';
import { AccountService } from './account.service';
import { BlockusService } from './blockus.service';
import {
  SendVerificationCodeDto,
  VerifyVerificationCodeDto,
  RegisterViaEmailDto,
  GameRegisterViaEmailDto,
  LoginViaEmailDto,
  LoginViaEmailV1Dto,
  LogActionDto,
  LoginViaMetamaskDto,
  SendVerificationCodeforSignatureDto,
  RegisterViaGoogleDto,
  LoginViaGoogleDto,
  SendVerificationCodeforResetPasswordDto,
  ResetPasswordDto,
  UpdateAvatarDto,
  ChangePasswordDto,
  SwitchMetamaskWalletDto,
  UpdateBasicInfoDto,
  UpdateEmailDto,
  sendVerificationCodeforUpdateEmailDto,
  UpdateGoogleSocialAccountDto,
  DeleteGoogleSocialAccountDto,
  ReplaceWalletDto,
  RegisterViaFacebookDto,
  LoginViaFacebookDto,
  UpdateUsernameDto,
  RevokeFacebookFacebookDto,
  RegisterViaMetamaskDto,
  UpdateBlockusSuiWalletDto,
  usernameAvailability,
  emailAvailability,
  QuestionnaireDto,
} from './account.dto';
import { HttpSuccess } from '../utils/HttpSuccess';

@Controller('account')
export class AccountController {
  constructor(
    private readonly accountService: AccountService,
    private readonly blockusService: BlockusService,
  ) {}

  @Get('')
  @UseGuards(JwtAuthGuard)
  async getUserInfo(
    @Request()
    request: any,
  ) {
    try {
      const jwtToken = request.headers.authorization.replace('Bearer ', '');
      return new HttpSuccess(await this.accountService.getUserInfo(jwtToken));
    } catch (error) {
      return error;
    }
  }

  @Get('wallets/collections/:collectionId')
  @UseGuards(JwtAuthGuard)
  async getWalletCollect(
    @Param() param,
    @Request()
    request: any,
  ) {
    try {
      const jwtToken = request.headers.authorization
        .replace('Bearer ', '')
        .replace('bearer ', '');
      const collectionId = param.collectionId;
      return await this.blockusService.queryCollection(jwtToken, collectionId);
    } catch (error) {
      return error;
    }
  }

  @Get('wallet/sui')
  async getBlockusJWT(@Query('sectumsempra') sectumsempra: string) {
    try {
      return await this.accountService.getBlockusJWT(sectumsempra);
    } catch (error) {
      return error;
    }
  }

  @Get('availability')
  async isAccountAvailable(
    @Query('email') email: string,
    @Query('username') username: string,
  ) {
    return (
      (await this.accountService.checkIsEmailAvailable(email)) ===
        emailAvailability.EmailAvailable &&
      (await this.accountService.checkIsUsernameAvailable(username)) ===
        usernameAvailability.UsernameAvailable
    );
  }

  @Get('availability/email')
  async isEmailAvailable(@Query('email') email: string) {
    try {
      return await this.accountService.checkIsEmailAvailable(email);
    } catch (error) {
      return error;
    }
  }

  @Get('availability/username')
  async isUsernameAvailable(@Query('username') username: string) {
    try {
      return await this.accountService.checkIsUsernameAvailable(username);
    } catch (error) {
      return error;
    }
  }

  @Get('availability/address')
  async isAddressAvailable(@Query('address') address: string) {
    try {
      return await this.accountService.checkIsAddressAvailable(
        address.toLowerCase(),
      );
    } catch (error) {
      return error;
    }
  }

  @Get('email')
  async getEmailByUsername(@Query('username') username: string) {
    try {
      return await this.accountService.getEmailByUsername(username);
    } catch (error) {
      return error;
    }
  }

  @Get('status')
  async getAccountStatus(@Query('email') email: string) {
    try {
      return await this.accountService.getAccountStatus(email);
    } catch (error) {
      return error;
    }
  }

  @Get('code/reset')
  async getVerificationCodeAvailability(@Query('code') code: string) {
    try {
      return await this.accountService.getVerificationCodeAvailability(code);
    } catch (error) {
      return error;
    }
  }

  @Get('info/status')
  async getResetNeededInfo(@Query('uid') uid: string) {
    try {
      return await this.accountService.getResetNeededInfo(uid);
    } catch (error) {
      return error;
    }
  }

  @Post('log')
  async logAction(@Body() { action, data }: LogActionDto) {
    try {
      return await this.accountService.logAction(action, data);
    } catch (error) {
      return error;
    }
  }

  @Post('code/reset')
  async sendVerificationCodeforResetPassword(
    @Body() { email }: SendVerificationCodeforResetPasswordDto,
  ) {
    try {
      return await this.accountService.sendVerificationCodeforResetPassword(
        email,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('code/email')
  async sendVerificationCodeforUpdateEmail(
    @Body() { oldEmail, newEmail }: sendVerificationCodeforUpdateEmailDto,
  ) {
    try {
      return await this.accountService.sendVerificationCodeforUpdateEmail(
        oldEmail,
        newEmail,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('code/sign')
  async sendVerificationCodeforSignature(
    @Body() { address }: SendVerificationCodeforSignatureDto,
  ) {
    try {
      return await this.accountService.sendVerificationCodeforSignature(
        address,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('code/send')
  async sendVerificationCode(@Body() { email }: SendVerificationCodeDto) {
    try {
      return new HttpSuccess(
        await this.accountService.sendVerificationCode(email),
      );
    } catch (error) {
      return error;
    }
  }

  @Post('code/verify')
  async verifyVerificationCode(
    @Body() { code, email, address }: VerifyVerificationCodeDto,
  ) {
    try {
      return new HttpSuccess(
        await this.accountService.verifyVerificationCode(code, email, address),
      );
    } catch (error) {
      return error;
    }
  }

  @Post('register/email')
  async registerViaEmail(
    @Body()
    { email, username, hash1, newsLetterSubscription }: RegisterViaEmailDto,
  ) {
    try {
      return await this.accountService.registerViaEmail(
        email,
        username,
        hash1,
        newsLetterSubscription,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('register/game/email')
  async gameRegisterViaEmail(
    @Body()
    { email, code, hash1, referralId }: GameRegisterViaEmailDto,
  ) {
    try {
      return await this.accountService.gameRegisterViaEmail(
        email,
        code,
        hash1,
        referralId,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('register/google')
  async registerViaGoogle(
    @Body()
    {
      email,
      username,
      hash1,
      newsLetterSubscription,
      referralId,
    }: RegisterViaGoogleDto,
  ) {
    try {
      return await this.accountService.registerViaGoogle(
        email,
        username,
        hash1,
        newsLetterSubscription,
        referralId,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('register/facebook')
  async registerViaFacebook(
    @Body()
    {
      userID,
      email,
      username,
      hash1,
      newsLetterSubscription,
      referralId,
    }: RegisterViaFacebookDto,
  ) {
    try {
      return await this.accountService.registerViaFacebook(
        userID,
        email,
        username,
        hash1,
        newsLetterSubscription,
        referralId,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('questionnaire')
  @UseGuards(JwtAuthGuard)
  async submitQuestionnaire(
    @Body()
    questionnaire: QuestionnaireDto,
  ) {
    try {
      return await this.accountService.AddQuestionnaire(questionnaire);
    } catch (error) {
      return error;
    }
  }

  @Post('register/metamask')
  async registerViaMetamask(
    @Body() { address, signature, code }: RegisterViaMetamaskDto,
  ) {
    try {
      return {
        token: await this.accountService.registerViaMetamask(
          address,
          signature,
          code,
        ),
        code: 0,
      };
    } catch (error) {
      return error;
    }
  }

  @Post('login/email')
  async loginViaEmail(@Body() { email, hash1 }: LoginViaEmailDto) {
    try {
      return await this.accountService.loginViaEmail(email, hash1);
    } catch (error) {
      return error;
    }
  }

  @Post('login/email/v1')
  async loginViaEmaiV1(@Body() { email, hash1, password }: LoginViaEmailV1Dto) {
    try {
      return await this.accountService.loginViaEmailV1(email, hash1, password);
    } catch (error) {
      return error;
    }
  }

  @Post('login/metamask')
  async loginViaMetamask(@Body() { address, signature }: LoginViaMetamaskDto) {
    try {
      return await this.accountService.loginViaMetamask(address, signature);
    } catch (error) {
      return error;
    }
  }

  @Post('login/google')
  async loginViaGoogle(@Body() { email, hash1 }: LoginViaGoogleDto) {
    try {
      return await this.accountService.loginViaGoogle(email, hash1);
    } catch (error) {
      return error;
    }
  }

  @Post('login/facebook')
  async loginViaFacebook(@Body() { userID, hash1 }: LoginViaFacebookDto) {
    try {
      return await this.accountService.loginViaFacebook(userID, hash1);
    } catch (error) {
      return error;
    }
  }

  @Post('password')
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @Body()
    { oldPassword, newPassword, email }: ChangePasswordDto,
  ) {
    try {
      return await this.accountService.changePassword(
        oldPassword,
        newPassword,
        email,
      );
    } catch (error) {
      return error;
    }
  }

  @Post('wallet/metamask')
  @UseGuards(JwtAuthGuard)
  async switchMetamaskWallet(
    @Body()
    { email, wallet }: SwitchMetamaskWalletDto,
  ) {
    try {
      return await this.accountService.switchMetamaskWallet(email, wallet);
    } catch (error) {
      return error;
    }
  }

  @Post('wallet/sui')
  @UseGuards(JwtAuthGuard)
  async updateBlockusSuiWallet(
    @Body()
    { uid, address }: UpdateBlockusSuiWalletDto,
  ) {
    try {
      return await this.accountService.updateBlockusSuiWallet(uid, address);
    } catch (error) {
      return error;
    }
  }

  @Put('wallet')
  @UseGuards(JwtAuthGuard)
  async replaceWallet(
    @Body()
    { email, wallet }: ReplaceWalletDto,
  ) {
    try {
      return await this.accountService.replaceWallet(email, wallet);
    } catch (error) {
      return error;
    }
  }

  @Put('password')
  async resetPassword(
    @Body()
    { newPassword, code }: ResetPasswordDto,
  ) {
    try {
      return await this.accountService.resetPassword(newPassword, code);
    } catch (error) {
      return error;
    }
  }

  // TODO: security check needed
  @Put('username')
  async updateUsername(
    @Body()
    { email, username }: UpdateUsernameDto,
  ) {
    try {
      return await this.accountService.updateUsername(email, username);
    } catch (error) {
      return error;
    }
  }

  @Put('avatar')
  @UseGuards(JwtAuthGuard)
  async updateAvatar(
    @Body()
    { email, avatar }: UpdateAvatarDto,
  ) {
    try {
      return await this.accountService.updateAvatar(email, avatar);
    } catch (error) {
      return error;
    }
  }

  @Put('email')
  async updateEmail(
    @Body()
    { code }: UpdateEmailDto,
  ) {
    try {
      return await this.accountService.updateEmail(code);
    } catch (error) {
      return error;
    }
  }

  @Put('basicInfo')
  async updateBasicInfo(
    @Body()
    { oldEmail, newEmail, username }: UpdateBasicInfoDto,
  ) {
    try {
      return await this.accountService.updateBasicInfo(
        oldEmail,
        newEmail,
        username,
      );
    } catch (error) {
      return error;
    }
  }

  @Put('social/google')
  @UseGuards(JwtAuthGuard)
  async updateGoogleSocialAccount(
    @Body()
    { email, googleAccount }: UpdateGoogleSocialAccountDto,
  ) {
    try {
      return await this.accountService.updateGoogleSocialAccount(
        email,
        googleAccount,
      );
    } catch (error) {
      return error;
    }
  }

  @Delete('social/google')
  @UseGuards(JwtAuthGuard)
  async deleteGoogleSocialAccount(
    @Body()
    { email }: DeleteGoogleSocialAccountDto,
  ) {
    try {
      return await this.accountService.deleteGoogleSocialAccount(email);
    } catch (error) {
      return error;
    }
  }

  @Delete('revoke/facebook')
  async revokeFacebook(
    @Body()
    { userID }: RevokeFacebookFacebookDto,
  ) {
    try {
      return await this.accountService.revokeFacebook(userID);
    } catch (error) {
      return error;
    }
  }
}
