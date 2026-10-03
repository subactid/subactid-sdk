import { generateKeyPairSync } from 'node:crypto';

export const rsaPem = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string;
export const ecPem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string;
