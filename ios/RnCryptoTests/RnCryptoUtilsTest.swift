//
//  RnCryptoUtilsTest.swift
//  RnCryptoTests
//
//  Created by Robert on 1/6/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import XCTest
@testable import RnCrypto

class RnCryptoUtilsTest: XCTestCase {
    let sut = RnCryptoUtils()
 
    
    func testHexStringToBytesFail() throws {
        // Returns nil if hexString is not a valid hex string
        let bytes = sut.hexStringToBytes("imnotahexstring")
        XCTAssertNil(bytes)
    }
    
    
    func test16bytesHexStringToBytes() throws {
        let bytes = sut.hexStringToBytes("717cdf366fdcc9ce5e8c953c0e7327aa")
        let expectedBytes: [UInt8] = [113, 124, 223, 54, 111, 220, 201, 206, 94, 140, 149, 60, 14, 115, 39, 170]
        XCTAssertEqual(bytes, expectedBytes)
    }

    
    func test32bytesHexStringToBytes() throws {
        let bytes = sut.hexStringToBytes("278c30e05408d726737448525f41386c57d7b256973d8e5c1e5cd3f34073b9f0")
        let expectedBytes: [UInt8] = [39, 140, 48, 224, 84, 8, 215, 38, 115, 116, 72, 82, 95, 65, 56, 108, 87, 215, 178, 86, 151, 61, 142, 92, 30, 92, 211, 243, 64, 115, 185, 240]
        XCTAssertEqual(bytes, expectedBytes)
    }
  

}
