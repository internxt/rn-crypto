//
//  1rr.swift
//  RnCryptoTests
//
//  Created by Robert on 30/5/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import IDZSwiftCommonCrypto
import XCTest

@testable import RnCrypto

class AesCipherTest: XCTestCase {
  let sut = AesCipher()
  let utils = RnCryptoUtils()
  let validKey: [UInt8] = Array(repeating: 0, count: 32)
  let validIV: [UInt8] = Array(repeating: 0, count: 16)

  func testEncrypt() throws {
    let destination = NSTemporaryDirectory() + "/encrypt"
    let inputStream = InputStream.init(data: "test".data(using: .utf8)!)
    let outputStream = OutputStream(url: URL(fileURLWithPath: destination), append: true)

    let hexKey = "4ba9058b2efc8c7c9c869b6573b725aa8bf67aecb26d3ebd678e624565570e9c"
    let hexIv = "4ae6fcc4dd6ebcdb9076f2396d64da48"

    self.sut.encrypt(
      input: inputStream,
      output: outputStream!,
      key: self.utils.hexStringToBytes(hexKey),
      iv: self.utils.hexStringToBytes(hexIv),
      callback: { (error, status) in
        XCTAssertEqual(status, Status.success)
        XCTAssertEqual(error, nil)
      }
    )
  }

  func testDecrypt() throws {
    let encryptedBytes: [UInt8] = [
      97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168,
      164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97,
      24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0,
      19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150,
      210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163,
      219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51,
      34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9,
      44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168,
      164, 0, 19, 163, 219, 9, 44, 97, 24, 150, 210, 51, 34, 168, 164, 0, 19, 163, 219, 9, 44, 93,
      20, 197, 207, 93, 20, 197, 207, 93, 20, 197, 207,
    ]

    let destination = NSTemporaryDirectory() + "/plain"
    let inputStream = InputStream(data: Data(bytes: encryptedBytes, count: encryptedBytes.count))
    let outputStream = OutputStream(url: URL(fileURLWithPath: destination), append: true)

    let hexKey = "4ba9058b2efc8c7c9c869b6573b725aa8bf67aecb26d3ebd678e624565570e9c"
    let hexIv = "4ae6fcc4dd6ebcdb9076f2396d64da48"

    self.sut.decrypt(
      input: inputStream,
      output: outputStream!,
      key: self.utils.hexStringToBytes(hexKey),
      iv: self.utils.hexStringToBytes(hexIv),
      callback: { (error, status) in
        XCTAssertEqual(status, Status.success)
        XCTAssertEqual(error, nil)
      }
    )
  }

  func testBadIV() throws {
    let destination = NSTemporaryDirectory() + "/encrypt"
    let inputStream = InputStream.init(data: "teststring".data(using: .utf8)!)
    let outputStream = OutputStream(url: URL(fileURLWithPath: destination), append: true)

    let hexKey = "4ba9058b2efc8c7c9c869b6573b725aa8bf67aecb26d3ebd678e624565570e9c"

    self.sut.encrypt(
      input: inputStream,
      output: outputStream!,
      key: self.utils.hexStringToBytes(hexKey),
      iv: [UInt8](),
      callback: { (error, status) in
        XCTAssertEqual(status, nil)
        XCTAssertEqual(error, RnCryptoError.badIv)

      }
    )
  }

  // Test encryption to chunks with unaligned buffer and chunk sizes
  func testBufferOverflowWithUnalignedChunks() {
    // Testing with buffer size of 8KB and non-multiple chunk size of 7KB
    let testData = Data(repeating: 0x41, count: 16 * 1024)
    let chunkSize = 7 * 1024

    let outputs = [
      OutputStream(toMemory: ()),
      OutputStream(toMemory: ()),
      OutputStream(toMemory: ()),
    ]

    let expectation = XCTestExpectation(description: "Unaligned chunks test")

    sut.encryptToChunks(
      input: InputStream(data: testData), outputs: outputs,
      key: validKey, iv: validIV, chunkSize: chunkSize
    ) { error, status in
      XCTAssertNil(error)

      let chunks = outputs.map { $0.property(forKey: .dataWrittenToMemoryStreamKey) as! Data }

      XCTAssertEqual(chunks[0].count, 7168)  // First 7KB chunk
      XCTAssertEqual(chunks[1].count, 7168)  // Second 7KB chunk
      XCTAssertEqual(chunks[2].count, 2048)  // Remaining 2KB

      XCTAssertEqual(chunks.reduce(0) { $0 + $1.count }, testData.count)
      expectation.fulfill()
    }

    wait(for: [expectation], timeout: 5.0)
  }

  func testEncryptToChunks() {
      let testData = Array(repeating: UInt8(1), count: 100)
      let key = Array(repeating: UInt8(0), count: 32)
      let iv = Array(repeating: UInt8(0), count: 16)
      let partSize = 30

      let inputStream = InputStream(data: Data(testData))
      let outputStreams = [
          OutputStream(toMemory: ()),
          OutputStream(toMemory: ()),
          OutputStream(toMemory: ()),
          OutputStream(toMemory: ())
      ]
      
      inputStream.open()
      outputStreams.forEach { $0.open() }
      
      let expectation = XCTestExpectation(description: "Encryption test")
      var encryptError: RnCryptoError?

      sut.encryptToChunks(input: inputStream, outputs: outputStreams, key: key, iv: iv, chunkSize: partSize) { error, status in
          print("Input status:", inputStream.streamStatus.rawValue)
          print("Output status:", outputStreams.map { $0.streamStatus.rawValue })
          print("Error:", error ?? "nil")
          encryptError = error
          expectation.fulfill()
      }

      wait(for: [expectation], timeout: 5.0)
      XCTAssertNil(encryptError)
  }
  
  func testLargeEncryptToChunks() {
     let megabyte = 1024 * 1024
     let testData = Array(repeating: UInt8(1), count: 102 * megabyte)
     let key = Array(repeating: UInt8(0), count: 32)
     let iv = Array(repeating: UInt8(0), count: 16)
     let chunkSize = 30 * megabyte

     let inputStream = InputStream(data: Data(testData))
    let outputStreams = Array(repeating: OutputStream(toMemory: ()), count: 4)
     
     inputStream.open()
     outputStreams.forEach { $0.open() }
     
     let expectation = XCTestExpectation(description: "Large file encryption")
     var encryptError: RnCryptoError?

     sut.encryptToChunks(
         input: inputStream,
         outputs: outputStreams,
         key: key,
         iv: iv,
         chunkSize: chunkSize
     ) { error, status in
         encryptError = error
         expectation.fulfill()
     }

     wait(for: [expectation], timeout: 30.0)
     
     outputStreams.forEach { $0.close() }
     inputStream.close()
     
     XCTAssertNil(encryptError)
  }
  
  func testGigabyteEncryptToChunks() {
     let gigabyte = 1024 * 1024 * 1024
     let testData = Array(repeating: UInt8(1), count: gigabyte)
     let key = Array(repeating: UInt8(0), count: 32)
     let iv = Array(repeating: UInt8(0), count: 16)
     let chunkSize = 35 * 1024 * 1024 // 35MB chunk
     
     let inputStream = InputStream(data: Data(testData))
     let outputStreams = Array(repeating: OutputStream(toMemory: ()), count: 30)

     inputStream.open()
     outputStreams.forEach { $0.open() }
     
     let expectation = XCTestExpectation(description: "GB encryption")
     var encryptError: RnCryptoError?

     sut.encryptToChunks(
         input: inputStream,
         outputs: outputStreams,
         key: key,
         iv: iv,
         chunkSize: chunkSize
     ) { error, status in
         encryptError = error
         expectation.fulfill()
     }

     wait(for: [expectation], timeout: 60.0)
     
     outputStreams.forEach { $0.close() }
     inputStream.close()
     
     XCTAssertNil(encryptError)
  }
  
  func testEncryptDecryptCycle() {
     // Setup: Create test data - 1MB
     let megabyte = 1024 * 1024
     let testData = Array(repeating: UInt8(1), count: 1 * megabyte)
     let key = Array(repeating: UInt8(0), count: 32)
     let iv = Array(repeating: UInt8(0), count: 16)
     let chunkSize = 400 * 1024 // 400KB chunks

     // Prepare input/output streams
     let inputStream = InputStream(data: Data(testData))
     let outputs = [
         OutputStream(toMemory: ()),
         OutputStream(toMemory: ()),
         OutputStream(toMemory: ())
     ]
     
     inputStream.open()
     outputs.forEach { $0.open() }
     
     // 1. Test encryption in chunks
     let expectation = XCTestExpectation(description: "Test")
     var encryptError: RnCryptoError?

     sut.encryptToChunks(input: inputStream, outputs: outputs, key: key, iv: iv, chunkSize: chunkSize) { error, status in
         encryptError = error
         expectation.fulfill()
     }

     wait(for: [expectation], timeout: 5.0)
     XCTAssertNil(encryptError)
     
     // 2. Combine encrypted chunks
     var encryptedData = Data()
     for stream in outputs {
         if let data = stream.property(forKey: .dataWrittenToMemoryStreamKey) as? Data {
             encryptedData.append(data)
         }
     }
     XCTAssertGreaterThan(encryptedData.count, 0)

     // 3. Test decryption
     let decryptInput = InputStream(data: encryptedData)
     let decryptOutput = OutputStream(toMemory: ())
     decryptInput.open()
     decryptOutput.open()
     
     let decryptExpectation = XCTestExpectation(description: "Test")
     
     sut.decrypt(input: decryptInput, output: decryptOutput, key: key, iv: iv) { error, status in
         XCTAssertNil(error)
         decryptExpectation.fulfill()
     }
     
     wait(for: [decryptExpectation], timeout: 5.0)

     // 4. Verify original and decrypted data are equal
     guard let decryptedData = decryptOutput.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
         XCTFail("No decrypted data")
         return
     }
     
     XCTAssertEqual(testData, Array(decryptedData))
  }
}
