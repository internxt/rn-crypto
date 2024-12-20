import { Buffer } from 'buffer';
import { NativeModules, Platform } from 'react-native';
import { HMAC } from './types/crypto';
const LINKING_ERROR =
  `The package 'rn-crypto' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';
const RnCrypto = NativeModules.RnCrypto
  ? NativeModules.RnCrypto
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );
export function multiply(a, b) {
  return RnCrypto.multiply(a, b);
}
export function getDocumentsPath() {
  return RnCrypto.getDocumentsPath();
}
export function getDownloadsPath() {
  return RnCrypto.getDownloadsPath();
}
export function listDir(dir) {
  return RnCrypto.listDir(dir);
}
/**
 * Encrypts a given file in AES256-CTR writing it encrypted on the encryptedFilePath
 * @param plainFilePath Path where file is located
 * @param encryptedFilePath Path where file encrypted is going to be written
 * @param hexKey Encryption key in hex format
 * @param hexIv IV in hex format
 * @param cb Only error callback
 */
export function encryptFile(
  plainFilePath,
  encryptedFilePath,
  hexKey,
  hexIv,
  cb
) {
  RnCrypto.encryptFile(plainFilePath, encryptedFilePath, hexKey, hexIv, cb);
}
/**
 * Decrypts a given encrypted file, writing it decrypted on the plainFilePath
 * @param encryptedFilePath Path where encrypted file is located
 * @param plainFilePath Path where file decrypted is going to be written
 * @param hexKey Encryption key in hex format
 * @param hexIv IV in hex format
 * @param cb Only error callback
 */
export function decryptFile(
  encryptedFilePath,
  plainFilePath,
  hexKey,
  hexIv,
  cb
) {
  RnCrypto.decryptFile(encryptedFilePath, plainFilePath, hexKey, hexIv, cb);
}
function getNativeHMAC(hmac) {
  if (hmac === HMAC.sha256) {
    return RnCrypto.sha256;
  }
  if (hmac === HMAC.sha512) {
    return RnCrypto.sha512;
  }
}

export function joinFiles(inputFiles, outputFile) {
  return RnCrypto.joinFiles(inputFiles, outputFile);
}
/**
 * Creates a pbkdf2 key derivation
 *
 * @param password Password to use
 * @param salt Salt to use
 * @param rounds Rounds
 * @param derivedKeyLength Length of the derived key
 * @returns A buffer containing the result
 */
export async function pbkdf2(password, salt, rounds, derivedKeyLength) {
  const result = await RnCrypto.pbkdf2(
    password,
    salt,
    rounds,
    derivedKeyLength
  );
  return Buffer.from(result, 'hex');
}
/**
 * Creates a hash that can be updated
 * during the creation
 *
 * @param hmac HMAC to use
 * @returns A buffer containing the final hash
 */
export function createHash(hmac) {
  const values = [];
  const digest = async () => {
    const nativeHmac = getNativeHMAC(hmac);
    const hexResult = await nativeHmac(values);
    return Buffer.from(hexResult, 'hex');
  };
  const update = (value) => {
    if (typeof value === 'string') {
      values.push(Buffer.from(value).toString('hex'));
    } else {
      values.push(value.toString('hex'));
    }
    return {
      update,
      digest,
    };
  };
  return {
    update,
    digest,
  };
}
