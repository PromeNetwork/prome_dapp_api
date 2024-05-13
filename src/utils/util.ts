import { createHmac } from 'crypto';

export function generateShortIdFromUUID(uuid) {
  // 使用 SHA-1 哈希函数来转换 UUID
  const hmac = createHmac('sha256', 'a secret');

  const hash = hmac.update(uuid).digest('hex');

  // 从哈希值中提取前 8 位
  const shortId = hash.substring(0, 8);

  return shortId;
}

export function generateReferralCode(length) {
  // 定义字符池
  const characters =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;

  // 生成指定长度的随机字符串
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }

  return result;
}
