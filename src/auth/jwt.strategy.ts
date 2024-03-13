import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow('JWT_SECRET'),
    });
  }

  async validate(payload: any) {
    return {
      uid: payload.uid,
      email: payload.email,
      username: payload.username,
      particleJWT: payload.particleJWT,
      blockusJWT: payload.blockusJWT,
      wallets: payload.wallets,
      avatar: payload.avatar,
      social_payload_google: payload.social_payload_google,
      facebook_user_id: payload.facebook_user_id,
    };
  }
}
