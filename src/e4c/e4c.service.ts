import {
  Inject,
  Injectable,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import * as CryptoJS from 'crypto-js';
import { Pool } from 'pg';

import { AuthService } from '../auth/auth.service';

@Injectable()
export class E4cService {
  constructor(
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly pgPool: Pool,
  ) {}

  async readE4cAridropRecord(address: string) {
    try {
      const record = (
        await this.pgPool.query(
          `SELECT * FROM e4c_airdrop WHERE wallet = $1;`,
          [address],
        )
      ).rows[0];

      if (!record) {
        return new BadRequestException('Wallet address not found');
      }
      return record;
    } catch (error) {
      return error;
    }
  }

  async readE4cAridropEvent() {
    try {
      return {
        paymint_holder: {
          name: 'E4C Rangers Holder Airdrop',
          time: 1704441600000,
        },
        vote_1: {
          name: 'Community Governance Voting Event',
          time: 1705912200000,
        },
        top100_in_alpha_test: {
          name: 'Alpha Test Top Players Rewards',
          time: 1706247545000,
        },
        legend_of_e4c: {
          name: 'Legends of E4C: Share Your Epic Battles!',
          time: 1706528112000,
        },
        knowledge_challange: {
          name: 'Knowledge Challenge: Celebrating 2 Years with Ambrus Studio',
          time: 1706528712000,
        },
      };
    } catch (error) {
      return error;
    }
  }

  async readE4cHitoricalRecord(uid: string) {
    try {
      const accounts = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE uid = $1;`,
        [uid],
      );
      const account = accounts.rows[0];

      if (!account) return [];

      const recipient = [uid];

      if (account.wallets !== null) {
        recipient.push(account.wallets[0].address);
      }

      const record = (
        await this.pgPool.query(
          `SELECT * FROM e4c_record WHERE   recipient = ANY($1);`,
          [[recipient]],
        )
      ).rows;

      return record;
    } catch (error) {
      return error;
    }
  }

  async readE4cTx(txid: string) {
    try {
      const tx = (
        await this.pgPool.query(`SELECT * FROM e4c_record WHERE tx_id = $1;`, [
          txid,
        ])
      ).rows;

      return tx;
    } catch (error) {
      return error;
    }
  }

  async readE4cBalance(uid: string) {
    try {
      const record = await this.readE4cHitoricalRecord(uid);
      let sum = 0;

      record.map((x) => {
        sum += x.e4c;
      });

      return sum;
    } catch (error) {
      return error;
    }
  }

  async createE4cRecord(avadakedavra: string) {
    try {
      if (await this.cache.get(`createE4cRecord:${avadakedavra}`)) {
        return new BadRequestException('request acknowledged');
      }

      const key = CryptoJS.enc.Utf8.parse(
        this.configService.getOrThrow('E4C_AES_KEY'),
      );
      const iv = CryptoJS.enc.Utf8.parse(
        this.configService.getOrThrow('E4C_AES_IV'),
      );

      const bytes = CryptoJS.AES.decrypt(
        decodeURIComponent(avadakedavra),
        key,
        {
          iv: iv,
        },
      );

      const payload = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

      const description = 'description' in payload ? payload.description : '';
      const tag = 'tag' in payload ? payload.tag : '';
      const txId = 'txId' in payload ? payload.txId : '';

      if (
        !('recipient' in payload) ||
        !('e4c' in payload) ||
        !('requestTimestamp' in payload) ||
        typeof description !== 'string' ||
        typeof tag !== 'string' ||
        typeof txId !== 'string'
      ) {
        return new BadRequestException('invalid argument');
      }

      const now = new Date().getTime();
      if (now > +payload.requestTimestamp + 1000 * 60) {
        return new BadRequestException('request timeout');
      }

      const record = (
        await this.pgPool.query(
          `INSERT INTO e4c_record (recipient, e4c, timestamp, description, tag, tx_id)
            VALUES ($1, $2, $3, $4, $5, $6) returning *;`,
          [
            payload.recipient,
            payload.e4c,
            payload.requestTimestamp,
            description,
            tag,
            txId,
          ],
        )
      ).rows[0];
      delete record.id;

      await this.cache.set(`createE4cRecord:${avadakedavra}`, true, 1000 * 60);

      return record;
    } catch (error) {
      return new InternalServerErrorException();
    }
  }
}
