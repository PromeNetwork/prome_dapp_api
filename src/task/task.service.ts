import {
  Inject,
  Injectable,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { ConfigService } from '@nestjs/config';
import { Cache } from 'cache-manager';
import { Pool } from 'pg';
import { TaskType, type Task } from './task.dto';
import { generateReferralCode } from '../utils/util';
import { Client, auth } from 'twitter-api-sdk';
import needle from 'needle';
import e from 'express';

const endpointURL = 'https://api.twitter.com/2/tweets';
const STATE = 'my-state';
@Injectable()
export class TaskService {
  private twitterToken: string;
  private client: Client;
  constructor(
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
    private readonly configService: ConfigService,
    private readonly pgPool: Pool,
  ) {
    this.client = new Client(this.configService.get('TWITTER_BEAR_TOKEN'));
  }

  async getTweetLookup(ids: string[]) {
    const params = {
      ids: ids.join(','), // Edit Tweet IDs to look up
      'tweet.fields': 'lang,author_id', // Edit optional query parameters here
      'user.fields': 'created_at', // Edit optional query parameters here
    };

    // this is the HTTP header that adds bearer token authentication
    const res = await needle('get', endpointURL, params, {
      headers: {
        'User-Agent': 'v2TweetLookupJS',
        authorization: `Bearer ${this.twitterToken}`,
      },
    });
    if (res.body) {
      return res.body;
    } else {
      throw new Error('Unsuccessful request');
    }
  }

  async getTweetDetail(id: string) {
    try {
      const twitter = await this.client.tweets.findTweetById(id);
      return twitter;
    } catch (error) {
      throw new BadRequestException('Failed to query Twitter API');
    }
  }
  async queryTasks(address: string) {
    try {
      const tasks = (
        await this.pgPool.query(`SELECT * FROM task WHERE address = $1;`, [
          address.toLowerCase(),
        ])
      ).rows;
      return tasks;
    } catch (error) {
      console.log(error, address);
      throw new BadRequestException('Failed to query tasks');
    }
  }
  async addTwitterTask(task: Task) {
    try {
      //按照类型和地址查询是否已经存在

      const exist = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM task WHERE address = $1 AND type = $2);`,
          [task.address.toLowerCase(), task.type],
        )
      ).rows[0].exists;

      if (!exist) {
        const content = JSON.stringify({ content: task.content });
        await this.pgPool.query(
          `INSERT INTO task (address, type, status, content) VALUES ($1, $2, $3,$4);`,
          [task.address.toLowerCase(), task.type, task.status, content],
        );
        await this.processBranch(task.address.toLowerCase());
      } else {
        await this.pgPool.query(
          `UPDATE task SET status = $3 WHERE address = $1 AND type = $2;`,
          ['pending', task.address.toLowerCase(), task.type],
        );
      }
      return 'ok';
    } catch (error) {
      console.log(error, JSON.stringify(task));
      throw new BadRequestException('Failed to add task');
    }
  }

  /**
   * 根据地址查询用户完成任务情况，如果用户完成除SHARE 以外的所有任务
   * 则获得一张奖卷， 并且判断用户是否有父节点，如果有父节点则给父节点奖一张卷
   * @param address
   */
  async processBranch(address: string) {
    try {
      const tasks = (
        await this.pgPool.query(`SELECT * FROM task WHERE address = $1;`, [
          address,
        ])
      ).rows;
      const completeTasks = tasks.filter(
        (task) => task.type !== TaskType.SHARE && task.status === 'complete',
      );
      if (completeTasks.length === 5) {
        await this.pgPool.query(
          `INSERT INTO coupon (address, code, serial,status) VALUES ($1, $2, $3,$4) ON CONFLICT DO NOTHING ;`,
          [address, `PN${generateReferralCode(8)}`, 1, 0],
        );
        const parent = (
          await this.pgPool.query(
            `SELECT parent FROM account_v2 WHERE address = $1;`,
            [address],
          )
        ).rows[0];
        if (parent) {
          await this.pgPool.query(
            `INSERT INTO coupon (address, code, serial,status ) VALUES ($1, $2, $3, $4)ON CONFLICT DO NOTHING ;`,
            [parent, `PN${generateReferralCode(8)}`, 2, 0],
          );
        }
      }
    } catch (error) {
      throw new InternalServerErrorException('Failed to process branch');
    }
  }
  async addTask(task: Task) {
    try {
      await this.pgPool.query(
        `INSERT INTO task (address, type, status,content) VALUES ($1, $2, $3,$4);`,
        [task.address, task.type, task.status, task.content],
      );
      await this.processBranch(task.address);
      return true;
    } catch (error) {
      return false;
    }
  }

  async queryUserMe() {
    try {
      const meInfor = await this.client.users.findMyUser();
      return meInfor;
    } catch (error) {
      throw new BadRequestException('Failed to query Twitter API');
    }
  }
  async queryTwitterLike(token: string, userId: string) {
    try {
      const response = await fetch(
        `https://api.twitter.com/2/users/${userId}/liked_tweets`,
        {
          headers: {
            'User-Agent': 'v2LikedTweetsJS',
            authorization: `Bearer ${token}`,
          },
        },
      );
      return await response.json();
    } catch (error) {
      throw new BadRequestException('Failed to query Twitter API');
    }
  }

  async queryCoupons(address: string) {
    try {
      const coupons = (
        await this.pgPool.query(`SELECT * FROM coupon WHERE address = $1;`, [
          address,
        ])
      ).rows;
      return coupons;
    } catch (error) {
      return [];
    }
  }
}
