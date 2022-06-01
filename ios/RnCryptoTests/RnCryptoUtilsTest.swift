//
//  RnCryptoUtilsTest.swift
//  RnCryptoTests
//
//  Created by Robert on 1/6/22.
//  Copyright © 2022 Facebook. All rights reserved.
//
import Foundation
import XCTest
@testable import RnCrypto
@testable import IDZSwiftCommonCrypto



class RnCryptoUtilsTest: XCTestCase {
    let sut = RnCryptoUtils()
 
    
    func testHexStringToBytesFail() throws {
        // Throws a fatalError if string cannot be converted to bytes
        expectFatalError(expectedMessage: "convertHexDigit: Invalid hex digit") {
            self.sut.hexStringToBytes("imnotahexstring")
        }
       
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



// MARK: - fatalError testing
// See: https://marcosantadev.com/test-swift-fatalerror/
extension XCTestCase {
    func expectFatalError(expectedMessage: String, testcase: @escaping () -> Void) {
        
        let expectation = self.expectation(description: "expectingFatalError")
        var assertionMessage: String? = nil
        
        FatalErrorUtil.replaceFatalError { message, _, _ in
            assertionMessage = message
            expectation.fulfill()
            self.unreachable()
        }
        
        DispatchQueue.global(qos: .userInitiated).async(execute: testcase)
        
        waitForExpectations(timeout: 2) { _ in
            XCTAssertEqual(assertionMessage, expectedMessage)
            
            FatalErrorUtil.restoreFatalError()
        }
    }
    
    private func unreachable() -> Never {
        repeat {
            RunLoop.current.run()
        } while (true)
    }
}
