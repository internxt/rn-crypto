//
//  HMACTest.swift
//  RnCryptoTests
//
//  Created by Robert on 4/7/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import XCTest
@testable import RnCrypto

class HMACTest: XCTestCase {
    let sut = RnCryptoHMAC()
    let utils = RnCryptoUtils()

    func testSha512OneInput() throws {
        let result = sut.sha512(inputs: [utils.hexStringToBytes("95a242c82502cd2e4e791be67b3ebc4da8dd848cd2a9b42320a4eab72cc5d3b2f49662b088e652d8b2dd3916ad311b06bda7c70d5e0ed9b63d0bf6d1c164c9ec")])
        
        XCTAssertEqual(utils.bytesToHexString(result), "a5d4e36cd393aebd5dda84d2c207e9cd59f85016800303f710c25df7559556655e5ddaa4c91f47e63228f743a0fffa367972ae831e832ba75987fbe46aefb34c")
    }
    
    func testSha512MultipleInput() throws {
        let result = sut.sha512(inputs: [utils.hexStringToBytes("95a242c82502cd2e4e791be67b3ebc4da8dd848cd2a9b42320a4eab72cc5d3b2f49662b088e652d8b2dd3916ad311b06bda7c70d5e0ed9b63d0bf6d1c164c9ec"),utils.hexStringToBytes("95a242c82502cd2e4e791be67b3ebc4da8dd848cd2a9b42320a4eab72cc5d3b2f49662b088e652d8b2dd3916ad311b06bda7c70d5e0ed9b63d0bf6d1c164c9ec")])
        
       
        XCTAssertEqual(utils.bytesToHexString(result), "c681abb62f0af0fe21c175450d3844b32a3eb16ec52041b3acbdce9182eef685a0c2c04b560c9c1cbc2255cf63f56de9c4ba8bd42915291c414f1dc6b6323e3c")
    }

    

}
