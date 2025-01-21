package com.rncrypto;

import com.rncrypto.util.OnlyErrorCallback;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Executor;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptFileRepository {

  private final Executor executor;

  public EncryptFileRepository(Executor executor) {
    this.executor = executor;
  }

  public void encryptFileInBackground(
    String sourcePath,
    String destinationPath,
    byte[] key,
    byte[] iv,
    final OnlyErrorCallback callback
  ) {
    executor.execute(() ->
      encryptFile(sourcePath, destinationPath, key, iv, callback)
    );
  }

  public void encryptFile(
    String sourcePath,
    String destinationPath,
    byte[] key,
    byte[] iv,
    final OnlyErrorCallback onlyErrorCallback
  ) {
    try {
      this.encryptFile(
          sourcePath,
          destinationPath,
          this.getAES256CTRCipher(key, iv)
        );

      onlyErrorCallback.onComplete(null);
    } catch (
      IOException
      | NoSuchPaddingException
      | InvalidAlgorithmParameterException
      | NoSuchAlgorithmException
      | InvalidKeyException e
    ) {
      e.printStackTrace();
      onlyErrorCallback.onComplete(e);
    }
  }

  /**
   * Generates an AES-256-CTR Cipher
   *
   * @param key Cipher key
   * @param iv Initialization vector
   * @return Cipher used for encrypting with AES-256-CTR
   */
  private Cipher getAES256CTRCipher(byte[] key, byte[] iv)
    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
    SecretKeySpec secretKey = new SecretKeySpec(key, 0, key.length, "AES");
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

    if (
      !cipher.getAlgorithm().toUpperCase().startsWith(("AES/CTR"))
    ) throw new IllegalArgumentException(
      "Invalid algorithm, only AES/CTR mode supported"
    );

    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

    return cipher;
  }

  /**
   * Encrypts a file at sourcePath, writes the output to destinationPath
   *
   * @param sourcePath      Path where file to encrypt is
   * @param destinationPath Path where encrypted content is going to be written
   * @param cipher          Cipher used to encrypt the content
   */
  private void encryptFile(
    String sourcePath,
    String destinationPath,
    Cipher cipher
  ) throws IOException {
    this.encrypt(
        new FileInputStream(sourcePath),
        new FileOutputStream(destinationPath),
        cipher
      );
  }

  /**
   * Encrypts content received from an input and writes it to an output
   *
   * @param inputStream  Source to encrypt
   * @param outputStream Source to write encrypted content
   * @param cipher       Cipher used to encrypt data
   */
  public void encrypt(
    InputStream inputStream,
    OutputStream outputStream,
    Cipher cipher
  ) throws IOException {
    CipherOutputStream cos = new CipherOutputStream(outputStream, cipher);

    int b;
    byte[] buffer = new byte[4096];

    while ((b = inputStream.read(buffer)) != -1) {
      cos.write(buffer, 0, b);
    }

    cos.flush();
    cos.close();
    inputStream.close();
  }

  public void encryptFileToChunks(
    String sourcePath,
    String[] destinationPaths,
    byte[] key,
    byte[] iv,
    int chunkSize,
    final OnlyErrorCallback callback
  ) {
    try (FileInputStream input = new FileInputStream(sourcePath)) {
      OutputStream[] outputs = new OutputStream[destinationPaths.length];

      for (int i = 0; i < destinationPaths.length; i++) {
        outputs[i] = new FileOutputStream(destinationPaths[i]);
      }
      Cipher cipher = getAES256CTRCipher(key, iv);
      encryptToMultipleChunks(input, outputs, cipher, chunkSize);
      callback.onComplete(null);
    } catch (Exception e) {
      callback.onComplete(e);
    }
  }

  public void encryptToMultipleChunks(
    InputStream inputStream,
    OutputStream[] outputs,
    Cipher cipher,
    int chunkSize
  ) throws IOException, BadPaddingException, IllegalBlockSizeException {
    if (chunkSize <= 0) {
      throw new IllegalArgumentException(
        "Chunk size must be greater than zero."
      );
    }
    if (outputs == null || outputs.length == 0) {
      throw new IllegalArgumentException("Outputs array cannot be empty.");
    }

    byte[] buffer = new byte[4096];
    int currentChunkIndex = 0;
    int bytesWrittenInChunk = 0;
    OutputStream currentOutput = outputs[currentChunkIndex];

    try {
      int bytesRead;

      while ((bytesRead = inputStream.read(buffer)) != -1) {
        int remaining = bytesRead;
        int offset = 0;

        while (remaining > 0) {
          int spaceLeftInChunk = chunkSize - bytesWrittenInChunk;
          int bytesToWrite = Math.min(remaining, spaceLeftInChunk);

          byte[] encryptedData = cipher.update(buffer, offset, bytesToWrite);
          if (encryptedData != null) {
            currentOutput.write(encryptedData);
          }

          remaining -= bytesToWrite;
          offset += bytesToWrite;
          bytesWrittenInChunk += bytesToWrite;

          if (bytesWrittenInChunk >= chunkSize && remaining > 0) {
            byte[] finalBlock = cipher.update(new byte[0]);
            if (finalBlock != null) {
              currentOutput.write(finalBlock);
            }
            currentOutput.flush();
            currentOutput.close();

            currentChunkIndex++;
            if (currentChunkIndex >= outputs.length) {
              throw new IOException(
                "Not enough output streams for the file size"
              );
            }

            currentOutput = outputs[currentChunkIndex];
            bytesWrittenInChunk = 0;
          }
        }
      }

      byte[] finalBlock = cipher.doFinal();
      if (finalBlock != null) {
        currentOutput.write(finalBlock);
      }
      currentOutput.flush();
    } finally {
      for (int i = currentChunkIndex; i < outputs.length; i++) {
        try {
          outputs[i].close();
        } catch (IOException e) {
          System.err.println(
            "Error closing output stream " + i + ": " + e.getMessage()
          );
        }
      }

      try {
        inputStream.close();
      } catch (IOException e) {
        System.err.println("Error closing input stream: " + e.getMessage());
      }
    }
  }
}
