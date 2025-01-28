package com.rncrypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class EncryptFileRepositoryTest {

  private EncryptFileRepository repository;
  private DecryptFileRepository decryptRepository;
  private byte[] validKey;
  private byte[] validIv;
  private static final int TIMEOUT_SECONDS = 5;

  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  @Before
  public void setUp() {
    repository = new EncryptFileRepository(Runnable::run);
    decryptRepository = new DecryptFileRepository(Runnable::run);
    validKey = new byte[32];
    validIv = new byte[16];
    Arrays.fill(validKey, (byte) 0);
    Arrays.fill(validIv, (byte) 0);
  }

  private File createTestFile(byte[] data) throws IOException {
    File testFile = tempFolder.newFile();
    try (FileOutputStream fos = new FileOutputStream(testFile)) {
      fos.write(data);
    }
    return testFile;
  }

  @Test
  public void testNegativeChunkSize() throws Exception {
    byte[] testData = new byte[100];
    Arrays.fill(testData, (byte) 1);
    File sourceFile = createTestFile(testData);

    String[] destinationPaths = { tempFolder.newFile().getAbsolutePath() };

    CountDownLatch latch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      destinationPaths,
      validKey,
      validIv,
      -10, // negative chunk size
      error -> {
        encryptError[0] = error;
        latch.countDown();
      }
    );

    assertTrue(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertTrue(encryptError[0] instanceof IllegalArgumentException);
  }

  @Test
  public void testZeroChunkSize() throws Exception {
    byte[] testData = new byte[100];
    Arrays.fill(testData, (byte) 1);
    File sourceFile = createTestFile(testData);

    String[] destinationPaths = { tempFolder.newFile().getAbsolutePath() };

    CountDownLatch latch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      destinationPaths,
      validKey,
      validIv,
      0, // zero chunk size
      error -> {
        encryptError[0] = error;
        latch.countDown();
      }
    );

    assertTrue(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertTrue(encryptError[0] instanceof IllegalArgumentException);
  }

  @Test
  public void testNoOutputPaths() throws Exception {
    byte[] testData = new byte[100];
    Arrays.fill(testData, (byte) 1);
    File sourceFile = createTestFile(testData);

    String[] destinationPaths = new String[0];

    CountDownLatch latch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      destinationPaths,
      validKey,
      validIv,
      100,
      error -> {
        encryptError[0] = error;
        latch.countDown();
      }
    );

    assertTrue(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertTrue(encryptError[0] instanceof IllegalArgumentException);
  }

  @Test
  public void testPartSizeLessThanFileSizeMultiple() throws Exception {
    // Test data: 16KB
    byte[] testData = new byte[16 * 1024];
    Arrays.fill(testData, (byte) 0x41);
    File sourceFile = createTestFile(testData);

    String[] destinationPaths = {
      tempFolder.newFile().getAbsolutePath(),
      tempFolder.newFile().getAbsolutePath(),
    };

    CountDownLatch latch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      destinationPaths,
      validKey,
      validIv,
      8 * 1024, // 8KB chunks
      error -> {
        encryptError[0] = error;
        latch.countDown();
      }
    );

    assertTrue(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertNull(encryptError[0]);

    // Verify file sizes
    File chunk1 = new File(destinationPaths[0]);
    File chunk2 = new File(destinationPaths[1]);
    assertEquals(8 * 1024, chunk1.length());
    assertEquals(8 * 1024, chunk2.length());
  }

  @Test
  public void testPartSizeLessThanFileSizeNotMultiple() throws Exception {
    // Test data: 16KB
    byte[] testData = new byte[16 * 1024];
    Arrays.fill(testData, (byte) 0x41);
    File sourceFile = createTestFile(testData);

    String[] destinationPaths = {
      tempFolder.newFile().getAbsolutePath(),
      tempFolder.newFile().getAbsolutePath(),
      tempFolder.newFile().getAbsolutePath(),
    };

    CountDownLatch latch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      destinationPaths,
      validKey,
      validIv,
      7 * 1024, // 7KB chunks
      error -> {
        encryptError[0] = error;
        latch.countDown();
      }
    );

    assertTrue(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertNull(encryptError[0]);

    // Verify file sizes
    File chunk1 = new File(destinationPaths[0]);
    File chunk2 = new File(destinationPaths[1]);
    File chunk3 = new File(destinationPaths[2]);
    assertEquals(7 * 1024, chunk1.length());
    assertEquals(7 * 1024, chunk2.length());
    assertEquals(2 * 1024, chunk3.length());
  }

  @Test
  public void testChunkSizeIntegerOverflow() throws Exception {
    byte[] testData = new byte[100];
    Arrays.fill(testData, (byte) 1);
    File sourceFile = createTestFile(testData);

    String[] destinationPaths = { tempFolder.newFile().getAbsolutePath() };

    CountDownLatch latch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      destinationPaths,
      validKey,
      validIv,
      Integer.MAX_VALUE,
      error -> {
        encryptError[0] = error;
        latch.countDown();
      }
    );

    assertTrue(latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertTrue(encryptError[0] instanceof IllegalArgumentException);
  }

  @Test
  public void testEncryptDecryptCycle() throws Exception {
    // Setup: Create test data - 1MB
    byte[] testData = new byte[1024 * 1024]; // 1MB
    Arrays.fill(testData, (byte) 1);
    File sourceFile = createTestFile(testData);

    // Create temporary files for encrypted chunks
    int chunkSize = 400 * 1024; // 400KB chunks
    String[] encryptedPaths = {
      tempFolder.newFile().getAbsolutePath(),
      tempFolder.newFile().getAbsolutePath(),
      tempFolder.newFile().getAbsolutePath()
    };

    // 1. Encrypt in chunks
    CountDownLatch encryptLatch = new CountDownLatch(1);
    final Exception[] encryptError = new Exception[1];

    repository.encryptFileToChunks(
      sourceFile.getAbsolutePath(),
      encryptedPaths,
      validKey,
      validIv,
      chunkSize,
      error -> {
        encryptError[0] = error;
        encryptLatch.countDown();
      }
    );

    assertTrue(encryptLatch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertNull("Encryption should not produce errors", encryptError[0]);

    // 2. Combine encrypted chunks into one file
    File combinedEncrypted = tempFolder.newFile();
    try (FileOutputStream fos = new FileOutputStream(combinedEncrypted)) {
      for (String path : encryptedPaths) {
        try (FileInputStream fis = new FileInputStream(path)) {
          byte[] buffer = new byte[4096];
          int bytesRead;
          while ((bytesRead = fis.read(buffer)) != -1) {
            fos.write(buffer, 0, bytesRead);
          }
        }
      }
    }

    // 3. Decrypt combined file
    File decryptedFile = tempFolder.newFile();
    CountDownLatch decryptLatch = new CountDownLatch(1);
    final Exception[] decryptError = new Exception[1];

    decryptRepository.decryptFile(
      combinedEncrypted.getAbsolutePath(),
      decryptedFile.getAbsolutePath(),
      validKey,
      validIv,
      error -> {
        decryptError[0] = error;
        decryptLatch.countDown();
      }
    );

    assertTrue(decryptLatch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    assertNull("Decryption should not produce errors", decryptError[0]);

    // 4. Verify original and decrypted data are equal
    try (FileInputStream fis = new FileInputStream(decryptedFile)) {
      byte[] decryptedData = new byte[testData.length];
      int bytesRead = fis.read(decryptedData);
      assertEquals("Decrypted file size should match original", testData.length, bytesRead);
      assertArrayEquals("Decrypted data should match original", testData, decryptedData);
    }

    // Verify expected chunk sizes
    long expectedFullChunkSize = 400 * 1024;
    long remainingBytes = testData.length % chunkSize;

    for (int i = 0; i < encryptedPaths.length - 1; i++) {
      File chunk = new File(encryptedPaths[i]);
      assertEquals("Full chunk size should be " + expectedFullChunkSize + " bytes",
        expectedFullChunkSize, chunk.length());
    }

    // Verify last chunk size if it's not a full chunk
    if (remainingBytes > 0) {
      File lastChunk = new File(encryptedPaths[encryptedPaths.length - 1]);
      assertEquals("Last chunk should contain remaining bytes",
        remainingBytes, lastChunk.length());
    }
  }
}
