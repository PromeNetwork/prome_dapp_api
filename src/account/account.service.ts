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
import { createTransport } from 'nodemailer';
import { readFileSync } from 'fs';
import { Pool } from 'pg';
import * as sha256 from 'crypto-js/sha256';
import * as CryptoJS from 'crypto-js';
import { pbkdf2Sync } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { bufferToHex } from '@ethereumjs/util';
import { recoverPersonalSignature } from '@metamask/eth-sig-util';
import * as jwt from 'jsonwebtoken';

import {
  usernameAvailability,
  emailAvailability,
  loginStatus,
  registerSatatus,
  accountStatus,
  WalletType,
  Wallet,
} from './account.dto';
import { AuthService } from '../auth/auth.service';

const RESET_PASSWORD_TIMEOUT = 3 * 60 * 1000;
const ALPHA_TEST_PRE_REGISTER_ENDTIME = 1704758400000;
const ALPHA_TEST_TIME = [1704758400000, 1705507200000];

@Injectable()
export class AccountService {
  private reservedWords: Array<string>;
  private sendCodeQueue: Array<any>;
  private verificationCodeEmailTemplate: string;
  private resetPasswordEmailTemplate: string;
  private senderEmail: string;
  private resetPasswordUrl: string;
  private emailTransporter: any;

  constructor(
    @Inject(CACHE_MANAGER) private readonly cache: Cache,
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly pgPool: Pool,
  ) {
    this.sendCodeQueue = [];
    this.reservedWords = readFileSync(
      configService.getOrThrow('RESERVED_WORDS_FILE'),
      'utf8',
    )
      .toString()
      .split('\n');
    this.verificationCodeEmailTemplate = readFileSync(
      this.configService.getOrThrow('VERIFICATION_CODE_EMAIL_TEMPLATE'),
      'utf-8',
    );
    this.resetPasswordEmailTemplate = readFileSync(
      this.configService.getOrThrow('RESET_PASSWORD_EMAIL_TAMPLATE'),
      'utf-8',
    );
    this.senderEmail = this.configService.getOrThrow('EMAIL_ACCOUNT_ADDRESS');
    this.resetPasswordUrl = this.configService.getOrThrow('RESET_PASSWORD_URL');
    this.emailTransporter = createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      pool: true,
      auth: {
        user: this.senderEmail,
        pass: this.configService.getOrThrow('EMAIL_PASSWORD'),
      },
    });
    this.__sendVerificationCode();
  }

  checkIsUsernameContainSensitiveWord(username: string) {
    for (const word of this.reservedWords) {
      if (word.length === 0) {
        continue;
      }
      const regex = new RegExp(word, 'i');
      if (regex.test(username)) {
        return true;
      }
    }
    return false;
  }

  checkIsUsernameHasIllegalCharacter(username: string) {
    const regex = new RegExp(/^[A-Za-z\d-_]+$/);

    if (!regex.test(username)) {
      return true;
    }
    return false;
  }

  checkIsUsernameLengthNotMatch(username: string) {
    return username.length < 5 && username.length > 35;
  }

  checkIsEmailLegal(email: string) {
    const emailRegex = new RegExp(
      /\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*/,
    );
    if (!email) return false;
    if (email.length > 254) return false;
    if (!emailRegex.test(email)) return false;
    const parts = email.split('@');
    if (parts[0].length > 64) return false;
    const domainParts = parts[1].split('.');
    if (
      domainParts.some(function (part) {
        return part.length > 63;
      })
    )
      return false;
    return true;
  }

  async checkIsUsernameAvailable(username: string) {
    if (this.checkIsUsernameContainSensitiveWord(username))
      return usernameAvailability.ContainSensitiveWord;
    if (this.checkIsUsernameHasIllegalCharacter(username))
      return usernameAvailability.HasIllegalCharacter;
    if (this.checkIsUsernameLengthNotMatch(username))
      return usernameAvailability.LengthNotMatch;
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE username = $1);`,
          [username],
        )
      ).rows[0].exists;

      return exists
        ? usernameAvailability.AlreadyUsed
        : usernameAvailability.UsernameAvailable;
    } catch (error) {
      throw error;
    }
  }

  async checkIsAddressAvailable(address: string) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2, jsonb_array_elements(wallets) with ordinality arr(item_object) WHERE arr.item_object -> 'address' = $1);`,
          [`"${address}"`],
        )
      ).rows[0].exists;

      return exists;
    } catch (error) {
      return error;
    }
  }

  async checkIsEmailAvailable(email: string) {
    if (!this.checkIsEmailLegal(email)) return emailAvailability.Illegalformat;

    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE email = $1);`,
          [email],
        )
      ).rows[0].exists;
      return exists
        ? emailAvailability.AlreadyUsed
        : emailAvailability.EmailAvailable;
    } catch (error) {
      throw error;
    }
  }

  async getEmailByUsername(username: string) {
    try {
      const email = (
        await this.pgPool.query(
          `SELECT email FROM account_v2 WHERE username = $1;`,
          [username],
        )
      ).rows[0].email;
      return email;
    } catch (error) {
      throw error;
    }
  }

  async getAccountStatus(email: string) {
    try {
      const account = (
        await this.pgPool.query(`SELECT * FROM account_v2 WHERE email = $1;`, [
          email,
        ])
      ).rows[0];

      if (!account) return accountStatus.Unregistered;
      return account.is_old_account
        ? accountStatus.OldAccount
        : accountStatus.NewAccount;
    } catch (error) {
      throw error;
    }
  }

  async logAction(action: string, data: any) {
    try {
      await this.pgPool.query(
        'INSERT INTO account_v2_action_log(timestamp, action, data) VALUES(now(), $1, $2);',
        [action, data],
      );
    } catch (error) {
      throw error;
    }
  }

  async sendVerificationCode(email: string) {
    const isEmailAvailable = await this.checkIsEmailAvailable(email);

    if (isEmailAvailable !== emailAvailability.EmailAvailable)
      throw new BadRequestException(isEmailAvailable);

    if (await this.cache.get(`verification-code:${email}`))
      throw new ConflictException();

    const code = randomstring.generate({
      length: 6,
      charset: 'numeric',
    });

    this.sendCodeQueue.push({ email, code, reqT: new Date().getTime() });

    return true;
  }

  async __sendVerificationCode() {
    if (this.sendCodeQueue.length !== 0) {
      const { email, code, reqT } = this.sendCodeQueue.shift();
      if (!(await this.cache.get(`verification-code:${email}`))) {
        this.sendVerificationCodeEmail(email, code, reqT);
      }
    }

    setTimeout(() => this.__sendVerificationCode(), 1000);
  }

  async sendVerificationCodeforUpdateEmail(oldEmail: string, newEmail: string) {
    try {
      let res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1;`,
        [oldEmail],
      );

      if (res.rows.length !== 1)
        return new BadRequestException('user not registered');

      const { register_type } = res.rows[0];
      if (register_type !== 'email')
        return new BadRequestException('not email account');

      res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1;`,
        [newEmail],
      );

      if (res.rows.length !== 0)
        return new BadRequestException('new email already used');

      const code = randomstring.generate({
        length: 6,
        charset: 'numeric',
      });
      try {
        await this.cache.set(
          `updateEmail:${code}`,
          { oldEmail, newEmail },
          10 * 60 * 1000,
        );
      } catch (error) {
        throw new InternalServerErrorException(error);
      }
      try {
        await this.sendVerificationCodeEmail(newEmail, code);
      } catch (error) {
        await this.cache.del(`updateEmail:${code}`);
        throw new InternalServerErrorException(error);
      }
      return true;
    } catch (error) {
      return error;
    }
  }

  async sendVerificationCodeforSignature(address: string) {
    const code = randomstring.generate({
      length: 8,
      charset: 'alphanumeric',
      capitalization: 'uppercase',
    });

    await this.cache.set(`code:${address}`, code, 300 * 1000);

    return code;
  }

  async sendVerificationCodeforResetPassword(email: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1;`,
        [email],
      );

      if (res.rows.length !== 1)
        return new BadRequestException('email not registered');

      const { register_type } = res.rows[0];
      if (register_type !== 'email')
        return new BadRequestException('not email account');

      const validTill = new Date().getTime() + RESET_PASSWORD_TIMEOUT;
      const ciphertext = JSON.stringify({ email, validTill });
      const code = encodeURIComponent(
        CryptoJS.AES.encrypt(
          ciphertext,
          this.configService.getOrThrow('AES_SECRET'),
        ).toString(),
      );
      try {
        await this.cache.set(
          `resetPassword:${code}`,
          email,
          RESET_PASSWORD_TIMEOUT,
        );
      } catch (error) {
        throw new InternalServerErrorException(error);
      }
      try {
        await this.sendResetPasswordEmail(email, code);
      } catch (error) {
        await this.cache.del(`resetPassword:${code}`);
        throw new InternalServerErrorException(error);
      }
      return true;
    } catch (error) {
      return error;
    }
  }

  async getVerificationCodeAvailability(code: string) {
    try {
      const key = `resetPassword:${code}`;
      const email = await this.cache.get<string>(key);
      return !!email;
    } catch (error) {
      return error;
    }
  }

  async getResetNeededInfo(uid: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT username, email, random_string, password_hash FROM account_v2 WHERE uid = $1 AND is_old_account = true;`,
        [uid],
      );
      if (res.rows.length !== 1)
        throw new NotFoundException(loginStatus.UserNotFound);
      const { username, email, random_string, password_hash } = res.rows[0];
      return {
        username: username.split('@')[0] === 'resetNeeded',
        email: email.split('@')[0] === 'undefinedemail',
        password:
          random_string.split('@')[0] === 'resetNeeded' ||
          password_hash.split('@')[0] === 'resetNeeded',
      };
    } catch (error) {
      throw error;
    }
  }

  async sendVerificationCodeEmail(email: string, code: string, reqT?: number) {
    try {
      await this.emailTransporter.sendMail({
        from: this.senderEmail,
        to: email,
        subject: 'Ambrus Studio Verification Code',
        html: this.verificationCodeEmailTemplate.replace('{CODE}', code),
      });
      await this.cache.set(`verification-code:${email}`, code, 60 * 1000);
      await this.cache.set(`verification-code:${code}`, email, 600 * 1000);
      await this.logAction('SendVerificationCodeSucc', {
        email,
        code,
        reqT,
        resT: new Date().getTime(),
      });
    } catch (error) {
      await this.logAction('SendVerificationCodeFail', {
        email,
        code,
        reqT,
        resT: new Date().getTime(),
        error,
      });
    }
  }

  async sendResetPasswordEmail(email: string, code: string) {
    try {
      await this.emailTransporter.sendMail({
        from: this.senderEmail,
        to: email,
        subject: 'E4C: Account Recovery',
        html: this.resetPasswordEmailTemplate.replace(
          '{URL}',
          `${this.resetPasswordUrl}${code}`,
        ),
      });
    } catch (error) {
      throw new InternalServerErrorException(error);
    }
  }

  async verifyVerificationCode(code: string, verifyAddress: string) {
    try {
      const email = await this.cache.get(`verification-code:${code}`);
      if (!email) {
        return new NotFoundException('Verification code not found');
      }

      if (email !== verifyAddress) {
        return new NotFoundException(
          'Verification code for this address not found',
        );
      } else {
        return true;
      }
    } catch (error) {
      throw error;
    }
  }

  async gameRegisterViaEmail(
    email: string,
    code: string,
    hash1: string,
    referralId: string,
  ) {
    try {
      const isEmailAvailable = await this.checkIsEmailAvailable(email);

      if (isEmailAvailable !== emailAvailability.EmailAvailable) {
        return new BadRequestException(isEmailAvailable);
      }
      const codeVerification = await this.verifyVerificationCode(code, email);
      if (codeVerification !== true) {
        return codeVerification;
      }

      const now = new Date().getTime();
      const uuid = uuidv4();
      const randomString = randomstring.generate({
        charset: 'alphanumeric',
      });
      const salt = `${now}${randomString}${uuid}`;
      const passwordHash = sha256(`${salt}${hash1}`).toString();
      const username = email.split('@')[0];
      const pass =
        now < ALPHA_TEST_PRE_REGISTER_ENDTIME
          ? 'premium_fast_pass'
          : 'alpha_test_pass';

      if (referralId) {
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, register_type, referrer, account_tag, game_package_id) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT DO NOTHING;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            false,
            'email',
            referralId,
            pass,
            '1',
          ],
        );
      } else {
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, register_type, account_tag, game_package_id) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            false,
            'email',
            pass,
            '1',
          ],
        );
      }

      return this.authService.generateToken({
        uid: uuid,
        email,
        username,
        wallets: [],
        blockus_sui_wallet: '',
        avatar: '',
        social_account_google: '',
        facebook_user_id: null,
        account_tag: pass,
      });
    } catch (error) {
      throw error;
    }
  }

  async registerViaEmail(
    email: string,
    username: string,
    hash1: string,
    newsLetterSubscription: boolean,
  ) {
    const now = new Date().getTime();
    const uuid = uuidv4();
    const randomString = randomstring.generate({
      charset: 'alphanumeric',
    });
    const salt = `${now}${randomString}${uuid}`;
    const passwordHash = sha256(`${salt}${hash1}`).toString();
    const pass =
      now < ALPHA_TEST_PRE_REGISTER_ENDTIME
        ? 'premium_fast_pass'
        : 'alpha_test_pass';

    try {
      await this.pgPool.query(
        `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, register_type, account_tag) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING;`,
        [
          uuid,
          username,
          email,
          true,
          now,
          randomString,
          passwordHash,
          newsLetterSubscription,
          'email',
          pass,
        ],
      );
      return this.authService.generateToken({
        uid: uuid,
        email,
        username,
        wallets: [],
        blockus_sui_wallet: '',
        avatar: '',
        social_account_google: '',
        facebook_user_id: null,
        account_tag: pass,
      });
    } catch (error) {
      throw error;
    }
  }

  async registerViaGoogle(
    email: string,
    username: string,
    hash1: string,
    newsLetterSubscription: boolean,
    referralId: string,
  ) {
    const isEmailAvailable = await this.checkIsEmailAvailable(email);

    if (isEmailAvailable !== emailAvailability.EmailAvailable)
      throw new BadRequestException(isEmailAvailable);

    if (
      sha256(
        `${email}${this.configService.getOrThrow('GOOGLE_PASSWORD_FLAVOR')}`,
      ).toString() !== hash1
    ) {
      throw new BadRequestException(registerSatatus.PasswordFlavorMismatch);
    }

    const now = new Date().getTime();
    const uuid = uuidv4();
    const randomString = randomstring.generate({
      charset: 'alphanumeric',
    });
    const salt = `${now}${randomString}${uuid}`;
    const passwordHash = sha256(`${salt}${hash1}`).toString();

    try {
      if (referralId) {
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, register_type, referrer) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            newsLetterSubscription,
            'google',
            referralId,
          ],
        );
      } else {
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, register_type) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            newsLetterSubscription,
            'google',
          ],
        );
      }
      return this.authService.generateToken({
        uid: uuid,
        email,
        username,
        wallets: [],
        blockus_sui_wallet: '',
        avatar: '',
        social_account_google: '',
        facebook_user_id: null,
        account_tag: '',
      });
    } catch (error) {
      throw error;
    }
  }

  async registerViaFacebook(
    userID: string,
    email: string,
    username: string,
    hash1: string,
    newsLetterSubscription: boolean,
    referralId: string,
  ) {
    const isEmailAvailable = await this.checkIsEmailAvailable(email);

    if (isEmailAvailable !== emailAvailability.EmailAvailable)
      throw new BadRequestException(isEmailAvailable);

    if (
      sha256(
        `${userID}${this.configService.getOrThrow('FACEBOOK_PASSWORD_FLAVOR')}`,
      ).toString() !== hash1
    ) {
      throw new BadRequestException(registerSatatus.PasswordFlavorMismatch);
    }

    const now = new Date().getTime();
    const uuid = uuidv4();
    const randomString = randomstring.generate({
      charset: 'alphanumeric',
    });
    const salt = `${now}${randomString}${uuid}`;
    const passwordHash = sha256(`${salt}${hash1}`).toString();

    try {
      if (referralId) {
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, third_party_login_field, register_type, referrer) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            newsLetterSubscription,
            userID,
            'facebook',
            referralId,
          ],
        );
      } else {
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, third_party_login_field, register_type) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT DO NOTHING;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            newsLetterSubscription,
            userID,
            'facebook',
          ],
        );
      }
      return this.authService.generateToken({
        uid: uuid,
        email,
        username,
        wallets: [],
        blockus_sui_wallet: '',
        avatar: '',
        social_account_google: '',
        facebook_user_id: userID,
        account_tag: '',
      });
    } catch (error) {
      throw error;
    }
  }

  async registerViaMetamask(address: string, signature: string) {
    try {
      const WalletAlreadyUsed = await this.checkIsAddressAvailable(address);

      if (WalletAlreadyUsed) {
        throw new BadRequestException(registerSatatus.WalletAlreadyUsed);
      }

      await this.verifySignature(address, signature);

      const uuid = uuidv4();
      const username = `resetNeeded@${uuid}`;
      const email = `undefinedemail@${uuid}`;
      const now = new Date().getTime();
      const randomString = `resetNeeded@${uuid}`;
      const passwordHash = `resetNeeded@${uuid}`;
      const wallets = JSON.stringify([
        {
          type: 'MetaMask',
          chain: 'Ethereum',
          address,
        },
      ]);
      const accountInfo = (
        await this.pgPool.query(
          `INSERT into account_v2(uid, username, email, is_email_verified, register_timestamp, random_string, password_hash, news_letter_subscription, register_type, is_old_account, wallets) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10. $11) ON CONFLICT DO NOTHING RETURNING *;`,
          [
            uuid,
            username,
            email,
            true,
            now,
            randomString,
            passwordHash,
            false,
            'email',
            true,
            wallets,
          ],
        )
      ).rows[0];

      return this.authService.generateToken(accountInfo);
    } catch (error) {
      return error;
    }
  }

  async loginViaEmail(email: string, hash1: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1;`,
        [email],
      );

      if (res.rows.length !== 1) {
        throw new NotFoundException(loginStatus.UserNotFound);
      }

      const {
        uid,
        username,
        register_timestamp,
        random_string,
        password_hash,
        is_email_verified,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        account_tag,
      } = res.rows[0];

      if (!is_email_verified)
        throw new ForbiddenException(loginStatus.EmailUnverified);

      const salt2 = `${register_timestamp}${random_string}${uid}`;
      const passwordHash2 = sha256(`${salt2}${hash1}`).toString();

      if (passwordHash2 === password_hash) {
        const now = new Date().getTime();
        if (now >= ALPHA_TEST_TIME[0] && now <= ALPHA_TEST_TIME[1]) {
          await this.pgPool.query(
            `INSERT INTO account_tag (uid, alpha_test)
            VALUES ($1, $2)
            ON CONFLICT (uid) DO UPDATE SET alpha_test = EXCLUDED.alpha_test;`,
            [uid, true],
          );
        }

        return this.authService.generateToken({
          uid,
          email,
          username,
          wallets,
          blockus_sui_wallet,
          avatar,
          social_account_google,
          facebook_user_id: null,
          account_tag,
        });
      } else {
        throw new BadRequestException(loginStatus.WrongPassword);
      }
    } catch (error) {
      throw error;
    }
  }

  async loginViaEmailV1(email: string, hash1: string, password: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1 AND is_old_account = true;`,
        [email],
      );

      if (res.rows.length !== 1) {
        throw new NotFoundException(loginStatus.UserNotFound);
      }

      const {
        uid,
        username,
        register_timestamp,
        random_string,
        password_hash,
        is_email_verified,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        account_tag,
      } = res.rows[0];

      if (!is_email_verified)
        throw new ForbiddenException(loginStatus.EmailUnverified);

      const hash = pbkdf2Sync(
        password,
        random_string,
        1000,
        64,
        'sha512',
      ).toString(`hex`);

      if (hash !== password_hash) {
        throw new BadRequestException(loginStatus.WrongPassword);
      }

      const randomString = randomstring.generate({
        charset: 'alphanumeric',
      });
      const salt = `${register_timestamp}${randomString}${uid}`;
      const passwordHash = sha256(`${salt}${hash1}`).toString();

      await this.pgPool.query(
        `UPDATE account_v2 SET random_string = $1, password_hash = $2, is_old_account = $3 WHERE email = $4;`,
        [randomString, passwordHash, false, email],
      );

      const now = new Date().getTime();
      if (now >= ALPHA_TEST_TIME[0] && now <= ALPHA_TEST_TIME[1]) {
        await this.pgPool.query(
          `INSERT INTO account_tag (uid, alpha_test)
          VALUES ($1, $2)
          ON CONFLICT (uid) DO UPDATE SET alpha_test = EXCLUDED.alpha_test;`,
          [uid, true],
        );
      }

      return this.authService.generateToken({
        uid,
        email,
        username,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        facebook_user_id: null,
        account_tag,
      });
    } catch (error) {
      throw error;
    }
  }

  async loginViaGoogle(email: string, hash1: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1;`,
        [email],
      );
      if (res.rows.length !== 1)
        throw new NotFoundException(loginStatus.UserNotFound);
      const {
        uid,
        username,
        register_timestamp,
        random_string,
        password_hash,
        is_email_verified,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        account_tag,
      } = res.rows[0];
      if (!is_email_verified)
        throw new ForbiddenException(loginStatus.EmailUnverified);
      const salt2 = `${register_timestamp}${random_string}${uid}`;
      const passwordHash2 = sha256(`${salt2}${hash1}`).toString();
      if (passwordHash2 === password_hash) {
        return this.authService.generateToken({
          uid,
          email,
          username,
          wallets,
          blockus_sui_wallet,
          avatar,
          social_account_google,
          facebook_user_id: null,
          account_tag,
        });
      } else {
        throw new BadRequestException(loginStatus.WrongPassword);
      }
    } catch (error) {
      throw error;
    }
  }

  async loginViaFacebook(userID: string, hash1: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE third_party_login_field = $1;`,
        [userID],
      );
      if (res.rows.length !== 1)
        throw new NotFoundException(loginStatus.UserNotFound);
      const {
        uid,
        email,
        username,
        register_timestamp,
        random_string,
        password_hash,
        is_email_verified,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        account_tag,
      } = res.rows[0];
      if (!is_email_verified)
        throw new ForbiddenException(loginStatus.EmailUnverified);
      const salt2 = `${register_timestamp}${random_string}${uid}`;
      const passwordHash2 = sha256(`${salt2}${hash1}`).toString();
      if (passwordHash2 === password_hash) {
        return this.authService.generateToken({
          uid,
          email,
          username,
          wallets,
          blockus_sui_wallet,
          avatar,
          social_account_google,
          facebook_user_id: userID,
          account_tag,
        });
      } else {
        throw new BadRequestException(loginStatus.WrongPassword);
      }
    } catch (error) {
      throw error;
    }
  }

  async loginViaMetamask(address: string, signature: string) {
    try {
      await this.verifySignature(address, signature);

      const res = await this.pgPool.query(
        `SELECT * FROM account_v2, jsonb_array_elements(wallets) with ordinality arr(item_object) WHERE arr.item_object -> 'address' = $1`,
        [`"${address}"`],
      );
      if (res.rows.length !== 1) {
        throw new NotFoundException(loginStatus.UserNotFound);
      }

      const {
        uid,
        username,
        email,
        is_email_verified,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        account_tag,
      } = res.rows[0];

      if (!is_email_verified) {
        throw new ForbiddenException(loginStatus.EmailUnverified);
      }

      return this.authService.generateToken({
        uid,
        email,
        username,
        wallets,
        blockus_sui_wallet,
        avatar,
        social_account_google,
        facebook_user_id: null,
        account_tag,
      });
    } catch (error) {
      return error;
    }
  }

  async verifySignature(address: string, signature: string) {
    const key = `code:${address}`;
    const code = await this.cache.get<string>(key);
    if (!code) {
      throw new BadRequestException('No code found');
    }

    await this.cache.del(key);

    const message = `Login Ambrus account center ${code}`;
    const actualAddress = recoverPersonalSignature({
      data: bufferToHex(Buffer.from(message, 'utf8')),
      signature,
    });

    if (actualAddress !== address) {
      throw new UnauthorizedException('Invalid signature');
    }
  }

  async updateWallet(email: string, wallet: Wallet) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT arr.item_object -> 'address' as address FROM account_v2, jsonb_array_elements(wallets) with ordinality arr(item_object) WHERE arr.item_object -> 'address' = $1);`,
          [`"${wallet.address}"`],
        )
      ).rows[0].exists;

      if (exists) {
        throw new BadRequestException(
          'Wallet address is already connected by others',
        );
      }

      const addresses = (
        await this.pgPool.query(
          `SELECT arr.item_object -> 'address' as address FROM account_v2, jsonb_array_elements(wallets) with ordinality arr(item_object) WHERE email = $1;`,
          [email],
        )
      ).rows[0];

      let res;

      if (addresses === undefined) {
        res = (
          await this.pgPool.query(
            `UPDATE account_v2 SET wallets = $1 WHERE email = $2 RETURNING *;`,
            [JSON.stringify([wallet]), email],
          )
        ).rows[0];
      } else {
        res = (
          await this.pgPool.query(
            `UPDATE account_v2 SET wallets = wallets || $1::jsonb WHERE email = $2 RETURNING *;`,
            [JSON.stringify(wallet), email],
          )
        ).rows[0];
      }

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      throw error;
    }
  }

  async updateBlockusSuiWallet(uid: string, address: string) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT blockus_sui_wallet FROM account_v2 WHERE blockus_sui_wallet = $1);`,
          [address],
        )
      ).rows[0].exists;

      if (exists) {
        throw new BadRequestException(
          'Wallet address is already connected by others',
        );
      }

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET blockus_sui_wallet = $1 WHERE uid = $2 RETURNING *;`,
          [address, uid],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      throw error;
    }
  }

  async replaceWallet(email: string, wallet: Wallet) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT arr.item_object -> 'address' as address FROM account_v2, jsonb_array_elements(wallets) with ordinality arr(item_object) WHERE arr.item_object -> 'address' = $1);`,
          [`"${wallet.address}"`],
        )
      ).rows[0].exists;

      if (exists) {
        throw new BadRequestException(
          'Wallet address is already connected by others',
        );
      }

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET wallets = $1 WHERE email = $2 RETURNING *;`,
          [JSON.stringify([wallet]), email],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      throw error;
    }
  }

  async switchMetamaskWallet(email: string, wallet: Wallet) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT arr.item_object -> 'address' as address FROM account_v2, jsonb_array_elements(wallets) with ordinality arr(item_object) WHERE arr.item_object -> 'address' = $1);`,
          [`"${wallet.address}"`],
        )
      ).rows[0].exists;

      if (exists) {
        throw new BadRequestException(
          'Wallet address is already connected by others',
        );
      }

      const wallets = (
        await this.pgPool.query(
          `SELECT wallets FROM account_v2 WHERE email = $1;`,
          [email],
        )
      ).rows[0];

      const newWallets = wallets.map((w: Wallet) => {
        if (w.type === WalletType.MetaMask) {
          w.address = wallet.address;
        }
      });

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET wallets = $1 WHERE email = $2 RETURNING *;`,
          [JSON.stringify(newWallets), email],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      throw error;
    }
  }

  async resetPassword(newHash1: string, code: string) {
    try {
      const key = `resetPassword:${code}`;
      const email = await this.cache.get<string>(key);

      if (!email) {
        throw new BadRequestException('No code found');
      }

      const bytes = CryptoJS.AES.decrypt(
        decodeURIComponent(code),
        this.configService.getOrThrow('AES_SECRET'),
      );
      const originalText = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
      const now = new Date().getTime();

      if (now > +originalText.validTill) {
        throw new BadRequestException('reset password timeout');
      }

      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1 AND register_type = 'email';`,
        [email],
      );
      if (res.rows.length !== 1)
        throw new NotFoundException(loginStatus.UserNotFound);

      const { register_timestamp, random_string, uid } = res.rows[0];
      const salt = `${register_timestamp}${random_string}${uid}`;
      const newPasswordHash = sha256(`${salt}${newHash1}`).toString();

      await this.pgPool.query(
        `UPDATE account_v2 SET password_hash = $1 ,is_old_account = $2 WHERE email = $3;`,
        [newPasswordHash, false, email],
      );
      await this.cache.del(key);
      return true;
    } catch (error) {
      return error;
    }
  }

  async changePassword(oldHash1: string, newHash1: string, email: string) {
    try {
      const res = await this.pgPool.query(
        `SELECT * FROM account_v2 WHERE email = $1 AND register_type = 'email';`,
        [email],
      );
      if (res.rows.length !== 1)
        throw new BadRequestException(loginStatus.UserNotFound);

      const {
        register_timestamp,
        random_string,
        password_hash,
        uid,
        wallets,
        is_old_account,
      } = res.rows[0];

      const metaMaskWalletAddress =
        wallets[0].type === 'MetaMask' ? wallets[0].address : null;
      const salt = `${register_timestamp}${random_string}${uid}`;
      const oldPasswordHash = sha256(`${salt}${oldHash1}`).toString();

      if (
        (oldPasswordHash !== password_hash && !is_old_account) ||
        (metaMaskWalletAddress !== oldHash1 && is_old_account)
      ) {
        throw new BadRequestException('current password not matched');
      }

      const newPasswordHash = sha256(`${salt}${newHash1}`).toString();

      if (is_old_account) {
        const randomString = randomstring.generate({
          charset: 'alphanumeric',
        });
        const newSalt = `${register_timestamp}${randomString}${uid}`;
        const passwordHash = sha256(`${newSalt}${newHash1}`).toString();

        const res = (
          await this.pgPool.query(
            `UPDATE account_v2 SET password_hash = $1, random_string = $2, is_old_account = $3  WHERE email = $4 RETURNING *;`,
            [passwordHash, randomString, false, email],
          )
        ).rows[0];

        return this.authService.generateToken(res);
      } else {
        const res = (
          await this.pgPool.query(
            `UPDATE account_v2 SET password_hash = $1 WHERE email = $2 RETURNING *;`,
            [newPasswordHash, email],
          )
        ).rows[0];
        return this.authService.generateToken(res);
      }
    } catch (error) {
      return error;
    }
  }

  async updateAvatar(email: string, avatar: string) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE email = $1);`,
          [email],
        )
      ).rows[0].exists;

      if (!exists) return new BadRequestException(loginStatus.UserNotFound);

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET avatar = $1 WHERE email = $2 RETURNING *;`,
          [avatar, email],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      return error;
    }
  }

  async getUserInfo(jwtToken: string) {
    try {
      const decodedToken = jwt.verify(
        jwtToken,
        this.configService.getOrThrow('JWT_SECRET'),
      );
      return decodedToken;
    } catch (error) {
      return error;
    }
  }

  async getBlockusJWT(sectumsempra: string) {
    try {
      const key = CryptoJS.enc.Utf8.parse(
        this.configService.getOrThrow('E4C_AES_KEY'),
      );
      const iv = CryptoJS.enc.Utf8.parse(
        this.configService.getOrThrow('E4C_AES_IV'),
      );

      const bytes = CryptoJS.AES.decrypt(
        decodeURIComponent(sectumsempra),
        key,
        {
          iv: iv,
        },
      );

      const { uid, requestTimestamp } = JSON.parse(
        bytes.toString(CryptoJS.enc.Utf8),
      );

      const now = new Date().getTime();

      if (now - +requestTimestamp > 1000 * 60) {
        return new BadRequestException('request JWT timeout');
      }

      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE uid = $1);`,
          [uid],
        )
      ).rows[0].exists;

      if (!exists) return new BadRequestException(loginStatus.UserNotFound);

      const blockusJWT = jwt.sign(
        {
          iss: 'Ambrus-studio',
          sub: uid,
          aud: 'blockus',
          exp: Math.floor(Date.now() / 1000) + 60 * 60,
          nbf: Math.floor(Date.now() / 1000),
        },
        this.configService.getOrThrow('BLOCKUS_SECRET_KEY'),
        {
          algorithm: 'RS256',
        },
      );
      return blockusJWT;
    } catch (error) {
      return error;
    }
  }

  async updateUsername(email: string, username: string) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE email = $1);`,
          [email],
        )
      ).rows[0].exists;

      if (!exists) return new BadRequestException(loginStatus.UserNotFound);

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET username = $1 WHERE email = $2 RETURNING *;`,
          [username, email],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      return error;
    }
  }

  async updateEmail(code: string) {
    try {
      const { oldEmail, newEmail } = await this.cache.get<{
        oldEmail: string;
        newEmail: string;
      }>(`updateEmail:${code}`);

      if (!oldEmail || !newEmail) {
        throw new BadRequestException('No code found');
      }

      let res = (
        await this.pgPool.query(`SELECT * FROM account_v2 WHERE email = $1;`, [
          oldEmail,
        ])
      ).rows[0];

      if (!res.uid) return new BadRequestException(loginStatus.UserNotFound);

      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE email = $1);`,
          [newEmail],
        )
      ).rows[0].exists;

      if (exists) return new BadRequestException(emailAvailability.AlreadyUsed);

      res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET email = $1 WHERE uid = $2 RETURNING *;`,
          [newEmail, res.uid],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      return error;
    }
  }

  async updateBasicInfo(oldEmail: string, newEmail: string, username: string) {
    if (newEmail === '' && username === '') {
      return new BadRequestException(
        'email and username cannot be empty at the same time',
      );
    }

    try {
      const uid = (
        await this.pgPool.query(
          `SELECT uid FROM account_v2 WHERE email = $1;`,
          [oldEmail],
        )
      ).rows[0].uid;
      if (!uid) return new BadRequestException(loginStatus.UserNotFound);

      if (newEmail === '') {
        const checkUsername = await this.checkIsUsernameAvailable(username);

        if (checkUsername !== usernameAvailability.UsernameAvailable) {
          return new BadRequestException(checkUsername);
        }

        await this.pgPool.query(
          `UPDATE account_v2 SET username = $1 WHERE uid = $2;`,
          [username, uid],
        );
      } else if (username === '') {
        const checkEmail = await this.checkIsEmailAvailable(newEmail);

        if (checkEmail !== emailAvailability.EmailAvailable) {
          return new BadRequestException(checkEmail);
        }

        await this.pgPool.query(
          `UPDATE account_v2 SET email = $1 WHERE uid = $2;`,
          [newEmail, uid],
        );
      } else {
        const checkUsername = await this.checkIsUsernameAvailable(username);

        if (checkUsername !== usernameAvailability.UsernameAvailable) {
          return new BadRequestException(checkUsername);
        }

        const checkEmail = await this.checkIsEmailAvailable(newEmail);

        if (checkEmail !== emailAvailability.EmailAvailable) {
          return new BadRequestException(checkEmail);
        }

        await this.pgPool.query(
          `UPDATE account_v2 SET email = $1, username = $2 WHERE uid = $3;`,
          [newEmail, username, uid],
        );
      }
      return true;
    } catch (error) {
      return error;
    }
  }

  async updateGoogleSocialAccount(email: string, googleAccount: string) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE email = $1);`,
          [email],
        )
      ).rows[0].exists;

      if (!exists) return new BadRequestException(loginStatus.UserNotFound);

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET social_account_google = $1 WHERE email = $2 RETURNING *;`,
          [googleAccount, email],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      return error;
    }
  }

  async deleteGoogleSocialAccount(email: string) {
    try {
      const exists = (
        await this.pgPool.query(
          `SELECT EXISTS(SELECT 1 FROM account_v2 WHERE email = $1);`,
          [email],
        )
      ).rows[0].exists;

      if (!exists) return new BadRequestException(loginStatus.UserNotFound);

      const res = (
        await this.pgPool.query(
          `UPDATE account_v2 SET social_account_google = null WHERE email = $1 RETURNING *;`,
          [email],
        )
      ).rows[0];

      if (res.third_party_login_field) {
        res.facebook_user_id = res.third_party_login_field;
      }

      return this.authService.generateToken(res);
    } catch (error) {
      return error;
    }
  }

  async revokeFacebook(userId: string) {
    return `${userId} 's account has been revoked.`;
  }
}
