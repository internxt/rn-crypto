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

  func testBufferOverflowWithUnalignedChunks() {
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

     XCTAssertEqual(encryptedData.count, testData.count)
    
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
  
  
  func testNoOutputStreams() {
      let testData = Array(repeating: UInt8(1), count: 1000)
      let partSize = 250
      
      let inputStream = InputStream(data: Data(testData))
      let outputStreams: [OutputStream] = []
      
      inputStream.open()
      
      let expectation = XCTestExpectation(description: "No streams test")
      var encryptError: RnCryptoError?
      
      sut.encryptToChunks(
          input: inputStream,
          outputs: outputStreams,
          key: validKey,
          iv: validIV,
          chunkSize: partSize
      ) { error, status in
          encryptError = error
          expectation.fulfill()
      }
      
      wait(for: [expectation], timeout: 5.0)
      XCTAssertEqual(encryptError, RnCryptoError.fileCreationFailed)
  }

  func testPartSizeEqualsFileSize() {
      let testData = Array(repeating: UInt8(1), count: 100)
      let partSize = 100
      
      let inputStream = InputStream(data: Data(testData))
      let outputStreams = [OutputStream(toMemory: ())]
      
      inputStream.open()
      outputStreams.forEach { $0.open() }
      
      let expectation = XCTestExpectation(description: "Equals file size")
      var encryptError: RnCryptoError?
      
      sut.encryptToChunks(
          input: inputStream,
          outputs: outputStreams,
          key: validKey,
          iv: validIV,
          chunkSize: partSize
      ) { error, status in
          encryptError = error
          expectation.fulfill()
      }
      
      wait(for: [expectation], timeout: 5.0)
      XCTAssertNil(encryptError)
      
      guard let encryptedData = outputStreams.first?.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
          XCTFail("No encrypted data")
          return
      }
      
      let decryptInput = InputStream(data: encryptedData)
      let decryptOutput = OutputStream(toMemory: ())
      decryptInput.open()
      decryptOutput.open()
      
      let decryptExpectation = XCTestExpectation(description: "Decryption")
      sut.decrypt(
          input: decryptInput,
          output: decryptOutput,
          key: validKey,
          iv: validIV
      ) { error, status in
          XCTAssertNil(error)
          decryptExpectation.fulfill()
      }
      
      wait(for: [decryptExpectation], timeout: 5.0)
      
      guard let decryptedData = decryptOutput.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
          XCTFail("No decrypted data")
          return
      }
      XCTAssertEqual(Array(decryptedData), testData)
  }
  
  func testPartSizeGreaterThanFileSize() {
      let testData = Array(repeating: UInt8(1), count: 100)
      let partSize = 200
      
      let inputStream = InputStream(data: Data(testData))
      let outputStreams = [OutputStream(toMemory: ())]
      
      inputStream.open()
      outputStreams.forEach { $0.open() }
      
      let expectation = XCTestExpectation(description: "Greater than file size")
      var encryptError: RnCryptoError?
      
      sut.encryptToChunks(
          input: inputStream,
          outputs: outputStreams,
          key: validKey,
          iv: validIV,
          chunkSize: partSize
      ) { error, status in
          encryptError = error
          expectation.fulfill()
      }
      
      wait(for: [expectation], timeout: 5.0)
      
      XCTAssertNil(encryptError)
      
      guard let encryptedData = outputStreams.first?.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
          XCTFail("No encrypted data")
          return
      }
      
      let decryptInput = InputStream(data: encryptedData)
      let decryptOutput = OutputStream(toMemory: ())
      decryptInput.open()
      decryptOutput.open()
      
      let decryptExpectation = XCTestExpectation(description: "Decryption")
      sut.decrypt(
          input: decryptInput,
          output: decryptOutput,
          key: validKey,
          iv: validIV
      ) { error, status in
          XCTAssertNil(error)
          decryptExpectation.fulfill()
      }
      
      wait(for: [decryptExpectation], timeout: 5.0)
      
      guard let decryptedData = decryptOutput.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
          XCTFail("No decrypted data")
          return
      }
      XCTAssertEqual(Array(decryptedData), testData)
  }

  func testPartSizeLessThanFileSizeMultiple() {
      let testData = Data(repeating: 0x41, count: 16 * 1024)
      let chunkSize = 8 * 1024
      
      let outputs = [
          OutputStream(toMemory: ()),
          OutputStream(toMemory: ())
      ]
      
      let expectation = XCTestExpectation(description: "Multiple chunks test")
      
      sut.encryptToChunks(
          input: InputStream(data: testData),
          outputs: outputs,
          key: validKey,
          iv: validIV,
          chunkSize: chunkSize
      ) { error, status in
          XCTAssertNil(error)
          
          let chunks = outputs.map { $0.property(forKey: .dataWrittenToMemoryStreamKey) as! Data }
          
          // Verify chunk count and sizes
          XCTAssertEqual(chunks.count, 2, "Should have 2 chunks")
          XCTAssertEqual(chunks[0].count, 8 * 1024, "First chunk should be 8KB")
          XCTAssertEqual(chunks[1].count, 8 * 1024, "Second chunk should be 8KB")
          
          // Verify total size matches
          XCTAssertEqual(chunks.reduce(0) { $0 + $1.count }, testData.count)
          
          // Verify decryption works
          var encryptedData = Data()
          chunks.forEach { encryptedData.append($0) }
          
          let decryptInput = InputStream(data: encryptedData)
          let decryptOutput = OutputStream(toMemory: ())
          decryptInput.open()
          decryptOutput.open()
          
          let decryptExpectation = XCTestExpectation(description: "Decryption")
          self.sut.decrypt(
              input: decryptInput,
              output: decryptOutput,
              key: self.validKey,
              iv: self.validIV
          ) { error, status in
              XCTAssertNil(error)
              
              guard let decryptedData = decryptOutput.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
                  XCTFail("No decrypted data")
                  return
              }
              
              XCTAssertEqual(decryptedData, testData)
              decryptExpectation.fulfill()
          }
          
          expectation.fulfill()
      }
      
      wait(for: [expectation], timeout: 5.0)
  }

  func testPartSizeLessThanFileSizeNotMultiple() {
      let testData = Data(repeating: 0x41, count: 16 * 1024)
      let chunkSize = 7 * 1024
      
      let outputs = [
          OutputStream(toMemory: ()),
          OutputStream(toMemory: ()),
          OutputStream(toMemory: ())
      ]
      
      let expectation = XCTestExpectation(description: "Non-multiple chunks test")
      
      sut.encryptToChunks(
          input: InputStream(data: testData),
          outputs: outputs,
          key: validKey,
          iv: validIV,
          chunkSize: chunkSize
      ) { error, status in
          XCTAssertNil(error)
          
          let chunks = outputs.map { $0.property(forKey: .dataWrittenToMemoryStreamKey) as! Data }
          
          // Verify chunk sizes
          XCTAssertEqual(chunks[0].count, 7168, "First chunk should be 7KB")
          XCTAssertEqual(chunks[1].count, 7168, "Second chunk should be 7KB")
          XCTAssertEqual(chunks[2].count, 2048, "Last chunk should be 2KB")
          
          // Verify total size matches
          XCTAssertEqual(chunks.reduce(0) { $0 + $1.count }, testData.count)
          
          // Verify decryption works
          var encryptedData = Data()
          chunks.forEach { encryptedData.append($0) }
          
          let decryptInput = InputStream(data: encryptedData)
          let decryptOutput = OutputStream(toMemory: ())
          decryptInput.open()
          decryptOutput.open()
          
          let decryptExpectation = XCTestExpectation(description: "Decryption")
          self.sut.decrypt(
              input: decryptInput,
              output: decryptOutput,
              key: self.validKey,
              iv: self.validIV
          ) { error, status in
              XCTAssertNil(error)
              
              guard let decryptedData = decryptOutput.property(forKey: .dataWrittenToMemoryStreamKey) as? Data else {
                  XCTFail("No decrypted data")
                  return
              }
              
              XCTAssertEqual(decryptedData, testData)
              decryptExpectation.fulfill()
          }
          
          expectation.fulfill()
      }
      
      wait(for: [expectation], timeout: 5.0)
  }
  
  func testNegativeChunkSize() {
        let testData = Array(repeating: UInt8(1), count: 100)
        let partSize = -10
        
        let inputStream = InputStream(data: Data(testData))
        let outputStreams = [OutputStream(toMemory: ())]
        
        inputStream.open()
        outputStreams.forEach { $0.open() }
        
        let expectation = XCTestExpectation(description: "Negative chunk size")
        var encryptError: RnCryptoError?
        
        sut.encryptToChunks(
            input: inputStream,
            outputs: outputStreams,
            key: validKey,
            iv: validIV,
            chunkSize: partSize
        ) { error, status in
            encryptError = error
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
        XCTAssertEqual(encryptError, RnCryptoError.badInput)
    }

    func testZeroChunkSize() {
        let testData = Array(repeating: UInt8(1), count: 100)
        let partSize = 0
        
        let inputStream = InputStream(data: Data(testData))
        let outputStreams = [OutputStream(toMemory: ())]
        
        inputStream.open()
        outputStreams.forEach { $0.open() }
        
        let expectation = XCTestExpectation(description: "Zero chunk size")
        var encryptError: RnCryptoError?
        
        sut.encryptToChunks(
            input: inputStream,
            outputs: outputStreams,
            key: validKey,
            iv: validIV,
            chunkSize: partSize
        ) { error, status in
            encryptError = error
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
        XCTAssertEqual(encryptError, RnCryptoError.badInput)
    }

   
  func testStreamReadError() {
      // mock to simulate reading error
      class MockInputStream: InputStream {
          override func read(_ buffer: UnsafeMutablePointer<UInt8>, maxLength len: Int) -> Int {
              return -1 // simulates read error
          }
          
          override var streamError: Error? {
              return NSError(domain: "", code: -1, userInfo: nil)
          }
          
          override var hasBytesAvailable: Bool {
              return true
          }
          
          override func open() {}
          
          override func close() {}
      }
      
      let inputStream = MockInputStream()
      let outputStreams = [OutputStream(toMemory: ())]
      
      inputStream.open()
      outputStreams.forEach { $0.open() }
      
      let expectation = XCTestExpectation(description: "Read error")
      var encryptError: RnCryptoError?
      
      sut.encryptToChunks(
          input: inputStream,
          outputs: outputStreams,
          key: validKey,
          iv: validIV,
          chunkSize: 100
      ) { error, status in
          encryptError = error
          expectation.fulfill()
      }
      
      wait(for: [expectation], timeout: 5.0)
      XCTAssertEqual(encryptError, RnCryptoError.readFailed)
  }

    func testChunkSizeIntegerOverflow() {
        let testData = Array(repeating: UInt8(1), count: 100)
        let partSize = Int.max
        
        let inputStream = InputStream(data: Data(testData))
        let outputStreams = [OutputStream(toMemory: ())]
        
        inputStream.open()
        outputStreams.forEach { $0.open() }
        
        let expectation = XCTestExpectation(description: "Integer overflow")
        var encryptError: RnCryptoError?
        
        sut.encryptToChunks(
            input: inputStream,
            outputs: outputStreams,
            key: validKey,
            iv: validIV,
            chunkSize: partSize
        ) { error, status in
            encryptError = error
            expectation.fulfill()
        }
        
        wait(for: [expectation], timeout: 5.0)
        XCTAssertEqual(encryptError, RnCryptoError.badInput)
    }
}
