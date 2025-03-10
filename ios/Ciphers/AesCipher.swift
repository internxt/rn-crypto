//
//  AES.swift
//  RnCrypto
//
//  Created by Robert on 30/5/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto

class AesCipher {
  var utils = RnCryptoUtils()
  let bufferSize = 1024 * 8
  private func isValidIv(iv: [UInt8]) -> Bool {
    return StreamCryptor.Algorithm.aes.blockSize() == iv.count
  }

  // Encrypts an input stream to an output stream given a key and an IV
  // using AES256 CTR mode with No padding
  public func encrypt(
    input: InputStream, output: OutputStream, key: [UInt8], iv: [UInt8],
    callback: (_: RnCryptoError?, _: Status?) -> Void
  ) {
    let algorithm = StreamCryptor.Algorithm.aes

    if !self.isValidIv(iv: iv) {
      return callback(RnCryptoError.badIv, nil)
    }

    let cryptStream = StreamCryptor(
      operation: StreamCryptor.Operation.encrypt,
      algorithm: algorithm,
      mode: StreamCryptor.Mode.CTR,
      padding: StreamCryptor.Padding.NoPadding,
      key: key,
      iv: iv
    )

    // Prepare buffers
    var inputBuffer = [UInt8](repeating: 0, count: bufferSize)
    var outputBuffer = [UInt8](repeating: 0, count: bufferSize)

    // Open streams
    input.open()
    output.open()

    var encryptedBytes: Int = 0
    while input.hasBytesAvailable {
      // Read the bytes
      let bytesRead = input.read(&inputBuffer, maxLength: inputBuffer.count)
      let status = cryptStream.update(
        bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer,
        byteCapacityOut: outputBuffer.count, byteCountOut: &encryptedBytes)

      if status != Status.success {
        // Handle this state, close streams and
        // notify via callback maybe?
      }
      // Make sure status is Ok
      if encryptedBytes > 0 {
        let bytesOut = output.write(outputBuffer, maxLength: encryptedBytes)
        assert(bytesOut == Int(encryptedBytes))
      }

    }

    // Final check
    let status = cryptStream.final(
      bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count,
      byteCountOut: &encryptedBytes)

    // Everything ok, close streams
    input.close()
    output.close()

    callback(nil, status)

  }

  // Encrypts an input stream to multiple output streams in chunks
  public func encryptToChunks(
    input: InputStream,
    outputs: [OutputStream],
    key: [UInt8],
    iv: [UInt8],
    chunkSize: Int,
    callback: (_ error: RnCryptoError?, _ status: Status?) -> Void
  ) {
    guard chunkSize > 0 else {
      return callback(.badInput, nil)
    }

    // To prevent integer overflow in later calculations
    guard Int.max - chunkSize > 0 else {
      return callback(.badInput, nil)
    }

    let algorithm = StreamCryptor.Algorithm.aes
    let bufferSize: Int = 1024 * 8

    guard isValidIv(iv: iv) else {
      return callback(.badIv, nil)
    }

    let cryptStream = StreamCryptor(
      operation: .encrypt,
      algorithm: algorithm,
      mode: .CTR,
      padding: .NoPadding,
      key: key,
      iv: iv
    )

    var inputBuffer = [UInt8](repeating: 0, count: bufferSize)
    var outputBuffer = [UInt8](repeating: 0, count: bufferSize)
    input.open()
    var encryptedBytes: Int = 0
    var chunkIndex = 0
    var bytesWrittenInChunk = 0
    var totalBytesProcessed: Int64 = 0

    guard !outputs.isEmpty else {
      input.close()
      return callback(.fileCreationFailed, nil)
    }

    defer {
      input.close()
      outputs.forEach { $0.close() }
    }

    outputs.forEach { $0.open() }

    func writeBytes(from buffer: [UInt8], offset: Int, length: Int) -> (
      bytesWritten: Int, error: RnCryptoError?
    ) {
      if chunkIndex >= outputs.count {
        return (0, .writeFailed)
      }
      let bytesOut = outputs[chunkIndex].write(
        Array(buffer[offset..<(offset + length)]), maxLength: length)
      if bytesOut <= 0 {
        return (0, .writeFailed)
      }
      return (bytesOut, nil)
    }

    while input.hasBytesAvailable {
      let bytesRead = input.read(&inputBuffer, maxLength: inputBuffer.count)

      if bytesRead < 0 {
        return callback(.readFailed, nil)
      } else if bytesRead == 0 {
        break
      }

      let status = cryptStream.update(
        bufferIn: inputBuffer,
        byteCountIn: bytesRead,
        bufferOut: &outputBuffer,
        byteCapacityOut: outputBuffer.count,
        byteCountOut: &encryptedBytes
      )

      if status != .success {
        return callback(.encryptionFailed, status)
      }

      var offset = 0
      var remainingBytes = encryptedBytes

      while remainingBytes > 0 {
        let spaceLeftInChunk = chunkSize - bytesWrittenInChunk
        let bytesToWrite = min(remainingBytes, spaceLeftInChunk)

        let (bytesWritten, error) = writeBytes(
          from: outputBuffer, offset: offset, length: bytesToWrite)
        if let error = error {
          return callback(error, nil)
        }

        offset += bytesWritten
        remainingBytes -= bytesWritten
        bytesWrittenInChunk += bytesWritten
        totalBytesProcessed += Int64(bytesWritten)

        if bytesWrittenInChunk >= chunkSize {
          chunkIndex += 1
          bytesWrittenInChunk = 0
        }
      }
    }

    let finalStatus = cryptStream.final(
      bufferOut: &outputBuffer,
      byteCapacityOut: outputBuffer.count,
      byteCountOut: &encryptedBytes
    )

    guard finalStatus == .success else {
      return callback(.encryptionFailed, finalStatus)
    }

    if encryptedBytes > 0 {
      let (_, error) = writeBytes(from: outputBuffer, offset: 0, length: encryptedBytes)
      if let error = error {
        return callback(error, nil)
      }
    }

    callback(nil, finalStatus)
  }
  // Decrypts an input stream to an output stream given a key and an IV
  // using AES256 CTR mode with No padding

  public func decrypt(
    input: InputStream, output: OutputStream, key: [UInt8], iv: [UInt8],
    callback: (_: RnCryptoError?, _: Status?) -> Void
  ) {

    if !self.isValidIv(iv: iv) {
      return callback(RnCryptoError.badIv, nil)
    }

    let cryptStream = StreamCryptor(
      operation: StreamCryptor.Operation.decrypt,
      algorithm: StreamCryptor.Algorithm.aes,
      mode: StreamCryptor.Mode.CTR,
      padding: StreamCryptor.Padding.NoPadding,
      key: key,
      iv: iv
    )

    // Prepare buffers
    var inputBuffer = [UInt8](repeating: 0, count: bufferSize)
    var outputBuffer = [UInt8](repeating: 0, count: bufferSize)

    // Open streams
    input.open()
    output.open()

    var encryptedBytes: Int = 0
    while input.hasBytesAvailable {

      // Read the bytes
      let bytesRead = input.read(&inputBuffer, maxLength: inputBuffer.count)
      let status = cryptStream.update(
        bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer,
        byteCapacityOut: outputBuffer.count, byteCountOut: &encryptedBytes)

      if status != Status.success {
        // Handle this state, close streams and
        // notify via callback maybe?
      }
      if encryptedBytes > 0 {
        let bytesOut = output.write(outputBuffer, maxLength: encryptedBytes)
        assert(bytesOut == Int(encryptedBytes))
      }

    }

    // Final check
    let status = cryptStream.final(
      bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count,
      byteCountOut: &encryptedBytes)

    // Close streams
    input.close()
    output.close()

    // All ok, notify via callback
    callback(nil, status)
  }
}
