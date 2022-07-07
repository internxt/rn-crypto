package com.rncrypto;

import android.os.Environment;

import androidx.annotation.NonNull;

import com.facebook.common.util.Hex;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;
import com.rncrypto.util.CryptoService;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@ReactModule(name = RnCryptoModule.NAME)
public class RnCryptoModule extends ReactContextBaseJavaModule {
  public static final String NAME = "RnCrypto";

  public RnCryptoModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  @ReactMethod
  public void getDocumentsPath(Promise promise) {
    promise.resolve(this.getReactApplicationContext().getFilesDir().getAbsolutePath());
  }

  @ReactMethod
  public void getDownloadsPath(Promise promise) {
    promise.resolve(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath());
  }

  @ReactMethod
  public void listDir(String dirPath, Promise promise) {
    try {
      File file = new File(dirPath);

      if (!file.exists()) {
        throw new Exception("Folder does not exist");
      }

      File[] files = file.listFiles();

      if (files == null) {
        promise.resolve(null);
        return;
      }

      WritableArray fileMaps = Arguments.createArray();

      for (File childFile : files) {
        WritableMap fileMap = Arguments.createMap();

        fileMap.putDouble("mtime", (double) childFile.lastModified() / 1000);
        fileMap.putString("name", childFile.getName());
        fileMap.putString("path", childFile.getAbsolutePath());
        fileMap.putDouble("size", (double) childFile.length());
        fileMap.putInt("type", childFile.isDirectory() ? 1 : 0);

        fileMaps.pushMap(fileMap);
      }

      promise.resolve(fileMaps);
    } catch (Exception ex) {
      ex.printStackTrace();
      promise.reject(ex);
    }
  }

  /**
   * Encrypts a file in background.
   *
   * @param sourcePath      Path where file is located
   * @param destinationPath Path where encrypted file is going to be written
   * @param hexKey          Encryption key in hex format
   * @param hexIv           Initialization vector in hex format
   * @param cb              Only error callback
   */
  @ReactMethod
  public void encryptFile(
    String sourcePath,
    String destinationPath,
    String hexKey,
    String hexIv,
    Callback cb
  ) {
    CryptoService.getInstance().encryptFile(
      sourcePath,
      destinationPath,
      hexKey,
      hexIv,
      true,
      (Exception ex) -> {
        if (ex == null) {
          cb.invoke((Object) null);
        } else {
          cb.invoke(ex);
        }
      }
    );
  }

  /**
   * Decrypts a file in background.
   *
   * @param sourcePath      Path where encrypted file is located
   * @param destinationPath Path where decrypted file is going to be written
   * @param hexKey          Decryption key in hex format
   * @param hexIv           Initialization vector in hex format
   * @param cb              Only error callback
   */
  @ReactMethod
  public void decryptFile(
    String sourcePath,
    String destinationPath,
    String hexKey,
    String hexIv,
    Callback cb
  ) {
    CryptoService.getInstance().decryptFile(
      sourcePath,
      destinationPath,
      hexKey,
      hexIv,
      true,
      (Exception ex) -> {
        if (ex == null) {
          cb.invoke((Object) null);
        } else {
          cb.invoke(ex);
        }
      }
    );
  }

  @ReactMethod
  public void sha256() {

  }

  @ReactMethod
  public void sha512(ReadableArray inputs, Promise promise) {
    List<byte[]> byteInputs = new ArrayList<byte[]>();

    for (int i = 0; i < inputs.size(); i++) {
      byteInputs.add(Hex.decodeHex(inputs.getString(i)));
    }

    try {
      byte[] result = CryptoService
        .getInstance().sha512(byteInputs);

      promise.resolve(Hex.encodeHex(result,false));
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      promise.reject("NO_ALGORITHM",e.getMessage());
    }

  }


  @ReactMethod
  public void pbkdf2(
    String password,
    String salt,
    Double rounds,
    Double derivedKeyLength,
    Promise promise
  ) {

    try {
      byte[] result = CryptoService
        .getInstance()
        .pbkdf2(password, salt.getBytes(),rounds.intValue(), derivedKeyLength.intValue());


      promise.resolve(Hex.encodeHex(result, false));
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      promise.reject("NO_ALGORITHM",e.getMessage());

    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      promise.reject("INVALID_KEY_SPEC",e.getMessage());
    }

  }

}
