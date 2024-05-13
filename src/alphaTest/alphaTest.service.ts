import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { Alchemy, Network } from 'alchemy-sdk';
import { Cache } from 'cache-manager';
import { Pool } from 'pg';

import { ServerRegion } from './alphaTest.dto';
import { AuthService } from '../auth/auth.service';

import { readFileSync } from 'fs';

@Injectable()
export class AlphaTestService {
  private alphaTestCompensationList: Array<string>;
  private alchemy: Alchemy;

  constructor(
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly pgPool: Pool,
  ) {
    this.alchemy = new Alchemy({
      network: Network[configService.getOrThrow('ALCHEMY_NETWORK')],
      apiKey: configService.getOrThrow('ALCHEMY_API_KEY'),
    });
    this.alphaTestCompensationList = readFileSync(
      configService.getOrThrow('ALPHA_TEST_COMPENSATION_LIST'),
      'utf8',
    )
      .toString()
      .split('\n');
  }

  async readAlphaTestRecord(uid: string) {
    try {
      let record = (
        await this.pgPool.query(
          `SELECT uid, score, e4c FROM alpha_test_record WHERE uid = $1;`,
          [uid],
        )
      ).rows[0];

      if (!record) {
        record = await this.createAlphaTestRecord(uid, 0, 0);
      }

      if (this.alphaTestCompensationList.includes(uid)) {
        record.e4c += 100;
      }

      return record;
    } catch (error) {
      return error;
    }
  }

  async createAlphaTestRecord(uid: string, score: number, e4c: number) {
    try {
      const res = (
        await this.pgPool.query(
          'INSERT INTO alpha_test_record(uid, score, e4c) VALUES($1, $2, $3) RETURNING uid, score, e4c;',
          [uid, score, e4c],
        )
      ).rows[0];
      return res;
    } catch (error) {
      return error;
    }
  }

  async updateAlphaTestRecord(uid: string, score: number, e4c: number) {
    try {
      const res = (
        await this.pgPool.query(
          'INSERT INTO alpha_test_record(uid, score, e4c) VALUES ($1, $2, $3) ON CONFLICT (uid) DO UPDATE SET score = EXCLUDED.score, e4c = EXCLUDED.e4c RETURNING uid, score, e4c;',
          [uid, score, e4c],
        )
      ).rows[0];
      return res;
    } catch (error) {
      return error;
    }
  }

  async readAlphaTestRecordV2(
    uid: string,
    serverRegion: ServerRegion | string,
  ) {
    if (!(serverRegion in ServerRegion) && serverRegion !== 'global')
      return new BadRequestException('server region not exist');

    try {
      let record = (
        await this.pgPool.query(
          `SELECT * FROM alpha_test_record_new WHERE uid = $1;`,
          [uid],
        )
      ).rows[0];

      if (!record) {
        record = await this.createAlphaTestRecordV2(
          uid,
          0,
          0,
          ServerRegion.america,
        );
      }

      const resp = { uid, score: 0, e4c: 0 };

      if (serverRegion === 'global') {
        for (const region in ServerRegion) {
          resp.score += +record[`score_${region}`];
          resp.e4c += +record[`e4c_${region}`];
        }
      } else {
        resp.score = record[`score_${serverRegion}`];
        resp.e4c = record[`e4c_${serverRegion}`];
      }

      return resp;
    } catch (error) {
      return error;
    }
  }

  async createAlphaTestRecordV2(
    uid: string,
    score: number,
    e4c: number,
    serverRegion: ServerRegion,
  ) {
    if (!(serverRegion in ServerRegion))
      return new BadRequestException('server region not exist');

    try {
      const res = (
        await this.pgPool.query(
          `INSERT INTO alpha_test_record_new(uid, score_${serverRegion}, e4c_${serverRegion}) VALUES($1, $2, $3) RETURNING *;`,
          [uid, score, e4c],
        )
      ).rows[0];
      return res;
    } catch (error) {
      return error;
    }
  }

  async updateAlphaTestRecordV2(
    uid: string,
    score: number,
    e4c: number,
    serverRegion: ServerRegion,
  ) {
    if (!(serverRegion in ServerRegion))
      return new BadRequestException('server region not exist');

    try {
      const res = (
        await this.pgPool.query(
          `INSERT INTO alpha_test_record_new(uid, score_${serverRegion}, e4c_${serverRegion}) VALUES ($1, $2, $3) ON CONFLICT (uid) DO UPDATE SET score_${serverRegion} = EXCLUDED.score_${serverRegion}, e4c_${serverRegion} = EXCLUDED.e4c_${serverRegion} RETURNING uid, score_${serverRegion} as score, e4c_${serverRegion} as e4c;`,
          [uid, score, e4c],
        )
      ).rows[0];
      return res;
    } catch (error) {
      return error;
    }
  }

  async readE4cAmountForPaymintHolder(address: string) {
    try {
      const res = (
        await this.pgPool.query(
          'select amount from e4c_for_paymint_holders where wallet = $1;',
          [address.toLowerCase()],
        )
      ).rows[0];
      return res ? res : { amount: 0 };
    } catch (error) {
      return error;
    }
  }

  async checkIfAddressHaveSBT(address: string) {
    try {
      const holdings = await this.alchemy.nft.getNftsForOwner(address, {
        contractAddresses: [
          this.configService.getOrThrow('SBT_CONTRACT_ADDRESS'),
        ],
      });

      return holdings.ownedNfts.length > 0;
    } catch (error) {
      return error;
    }
  }
}
