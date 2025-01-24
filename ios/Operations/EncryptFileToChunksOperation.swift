//
//  EncryptFileToChunksOperation.swift
//  RnCrypto
//
//  Created by Ramon Candel on 24/1/25.
//  Copyright © 2025 Facebook. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto

class EncryptFileToChunksOperation: Operation {
  var plainFileStream: InputStream?
  var encryptedFileStreams: [OutputStream]
  var hexIv: String
  var hexKey: String
  var chunkSize: Int

  var callback: (Error?) -> Void

  private var utils = RnCryptoUtils()
  private var aes = AesCipher()

  init(
    plainFilePath: URL, encryptedFilePaths: [URL], hexKey: String, hexIv: String, chunkSize: Int,
    callback: @escaping (Error?) -> Void
  ) {
    self.hexKey = hexKey
    self.hexIv = hexIv
    self.chunkSize = chunkSize
    self.callback = callback
    self.encryptedFileStreams = []

    do {
      guard let plainFileStream = InputStream(url: plainFilePath) else {
        throw RnCryptoError.plainFile
      }

      var streams: [OutputStream] = []
      for path in encryptedFilePaths {
        guard let stream = OutputStream(url: path, append: true) else {
          throw RnCryptoError.encryptedFile
        }
        streams.append(stream)
      }

      self.plainFileStream = plainFileStream
      self.encryptedFileStreams = streams
    } catch let error {
      print("Error preparing encrypt streams this will fail on Operation main() call", error)
    }
  }

  override func main() {
    if self.plainFileStream == nil {
      return self.callback(RnCryptoError.plainFile)
    }

    if self.encryptedFileStreams.isEmpty {
      return self.callback(RnCryptoError.encryptedFile)
    }

    let iv = self.utils.hexStringToBytes(self.hexIv)
    let key = self.utils.hexStringToBytes(self.hexKey)

    self.aes.encryptToChunks(
      input: self.plainFileStream!,
      outputs: self.encryptedFileStreams,
      key: key,
      iv: iv,
      chunkSize: self.chunkSize,
      callback: { (error, status) in
        self.callback(error)
      }
    )
  }
}
