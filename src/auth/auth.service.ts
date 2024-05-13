import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  decodeToken(token: string) {
    return this.jwtService.decode(token);
  }

  generateToken(account: {
    uid: any;
    email: any;
    username: any;
    wallets: any;
    blockus_sui_wallet: any;
    avatar: any;
    social_account_google: any;
    facebook_user_id: any;
    account_tag: any;
    random_string: any;
  }) {
    if (
      account.email &&
      account.email.split('@').length === 2 &&
      account.email.split('@')[0] === 'undefinedemail'
    ) {
      account.email = null;
    }

    return {
      accessToken: this.jwtService.sign({
        uid: account.uid,
        email: account.email,
        username: account.username,
        code: account.random_string,
        wallets: account.wallets,
        blockus_sui_wallet: account.blockus_sui_wallet,
        avatar: account.avatar,
        social_account_google: account.social_account_google,
        facebook_user_id: account.facebook_user_id,
        account_tag: account.account_tag,
      }),
    };
  }
}
