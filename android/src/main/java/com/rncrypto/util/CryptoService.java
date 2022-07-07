package com.rncrypto.util;

import com.facebook.common.util.Hex;
import com.rncrypto.DecryptFileRepository;
import com.rncrypto.EncryptFileRepository;
import com.rncrypto.ThreadPerTaskExecutor;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.Array;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class CryptoService {
  private static CryptoService instance = null;
  private final EncryptFileRepository encryptFileRepository;
  private final DecryptFileRepository decryptFileRepository;

  public CryptoService(EncryptFileRepository encryptFileRepository, DecryptFileRepository decryptFileRepository) {
    this.decryptFileRepository = decryptFileRepository;
    this.encryptFileRepository = encryptFileRepository;
  }

  private synchronized static void createInstance() {
    if (instance == null) {
      instance = new CryptoService(
        new EncryptFileRepository(new ThreadPerTaskExecutor()),
        new DecryptFileRepository(new ThreadPerTaskExecutor())
      );
    }
  }

  public static CryptoService getInstance() {
    if (instance == null) {
      createInstance();
    }
    return instance;
  }

  public static byte[] generateIv(int size) {
    byte[] iv = new byte[size];
    new SecureRandom().nextBytes(iv);

    return iv;
  }

  /**
   * Encrypts a file given in a sourcePath, writing output on destinationPath
   *
   * @param sourcePath
   * @param destinationPath
   * @param hexKey
   * @param hexIv
   * @param runInBackground Determines if encryption should be run on background
   * @param onlyErrorCallback
   */
  public void encryptFile(
    String sourcePath,
    String destinationPath,
    String hexKey,
    String hexIv,
    boolean runInBackground,
    OnlyErrorCallback onlyErrorCallback
  ) {
    byte[] key = Hex.decodeHex(hexKey);
    byte[] iv = Hex.decodeHex(hexIv);

    if (runInBackground) {
      this.encryptFileRepository.encryptFileInBackground(
        sourcePath,
        destinationPath,
        key,
        iv,
        onlyErrorCallback
      );
    } else {
      this.encryptFileRepository.encryptFile(
        sourcePath,
        destinationPath,
        key,
        iv,
        onlyErrorCallback
      );
    }
  }

  public void decryptFile(
    String sourcePath,
    String destinationPath,
    String hexKey,
    String hexIv,
    boolean runInBackground,
    OnlyErrorCallback onlyErrorCallback
  ) {
    byte[] key = Hex.decodeHex(hexKey);
    byte[] iv = Hex.decodeHex(hexIv);

    if (runInBackground) {
      this.decryptFileRepository.decryptFileInBackground(
        sourcePath,
        destinationPath,
        key,
        iv,
        onlyErrorCallback
      );
    } else {
      this.decryptFileRepository.decryptFile(
        sourcePath,
        destinationPath,
        key,
        iv,
        onlyErrorCallback
      );
    }
  }


  public byte[] pbkdf2(String password, byte[] salt, int rounds, int derivedKeyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, rounds,
      derivedKeyLength * 8);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
    SecretKey key = factory.generateSecret(spec);
    return key.getEncoded();
  }


  public byte[] sha512(List<byte[]> inputs) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-512");

    for(byte[] input: inputs) {
      md.update(input);
    }

    return md.digest();

  }
}
