import { generateKeyPairSync } from 'node:crypto';

export const rsaPem = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string;
export const ecPem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
  type: 'pkcs8',
  format: 'pem',
}) as string;

// The markers of a PKCS#8 PEM, read off a real one: a test that needs them does not spell them
// out, so no file holds text the secret scanner reads as a key.
const pemLines = ecPem.trim().split('\n');
export const pemBegin = pemLines[0] as string;
export const pemEnd = pemLines.at(-1) as string;
