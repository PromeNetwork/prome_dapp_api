import {
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import * as randomstring from 'randomstring';
import { Pool } from 'pg';
import * as sha256 from 'crypto-js/sha256';
import * as CryptoJS from 'crypto-js';
import { pbkdf2Sync } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { bufferToHex } from '@ethereumjs/util';
import { recoverPersonalSignature } from '@metamask/eth-sig-util';
import * as jwt from 'jsonwebtoken';
import { generateShortIdFromUUID } from '../utils/util';

import { AuthService } from '../auth/auth.service';

@Injectable()
export class BlockusService {
  private projectId: string;
  private projectKey: string;
  private collectId: string;
  private blockusUrl: string;
  private type: string;
  constructor(
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly pgPool: Pool,
  ) {
    this.projectId = this.configService.get('PROJECT_ID');
    this.projectKey = this.configService.get('PROJECT_KEY');
    this.collectId = this.configService.get('COLLECTION_ID');
    this.blockusUrl = this.configService.get('BLOCKUS_URL');
    this.type = this.configService.get('TYPE');
  }

  async loginBlocksu(blockusJWT: string) {
    const response = await fetch(`${this.blockusUrl}login?type=${this.type}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        accept: 'application/json',
        'X-PROJECT-KEY': this.projectKey,
        'X-PROJECT-ID': this.projectId,
      },
      body: JSON.stringify({ didToken: blockusJWT }),
    });
    const data: { accessToken: string } = await response.json();
    return data.accessToken;
  }

  async exchangeToken(jwtToken: string): Promise<string> {
    const decodeJwt = this.authService.decodeToken(jwtToken);
    if (!decodeJwt) {
      throw new BadRequestException('Invalid token');
    }
    if (decodeJwt['uid'] === undefined) {
      throw new UnauthorizedException('Invalid token');
    }
    const token = await this.cache.get(`blockus:${decodeJwt['uid']}`);
    if (token) {
      return token.toString();
    }
    const blockusJWT = jwt.sign(
      {
        iss: 'Ambrus-studio',
        sub: decodeJwt['uid'],
        aud: 'blockus',
        exp: Math.floor(Date.now() / 1000) + 60 * 60,
        nbf: Math.floor(Date.now() / 1000),
      },
      this.configService.getOrThrow('BLOCKUS_SECRET_KEY'),
      {
        algorithm: 'RS256',
      },
    );
    const clientToken = await this.loginBlocksu(blockusJWT);
    await this.cache.set(
      `blockus:${decodeJwt['uid']}`,
      clientToken,
      24 * 60 * 60 * 1000,
    );
    return clientToken;
  }

  async queryCollection(jwtToken: string, collectionId: string) {
    if (!jwtToken || jwtToken.length < 20) {
      throw new BadRequestException('Invalid token');
    }
    const token = await this.exchangeToken(jwtToken);
    const response = await fetch(
      `${this.blockusUrl}/wallets/collections/${collectionId}`,
      {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          accept: 'application/json',
          'X-ACCESS-TOKEN': token,
          'X-PROJECT-KEY': this.projectKey,
          'X-PROJECT-ID': this.projectId,
        },
      },
    );
    const data = await response.json();
    return data;
  }
}
