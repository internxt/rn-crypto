//
//  KeyDerivation.swift
//  RnCryptoTests
//
//  Created by Robert on 1/7/22.
//  Copyright © 2022 Facebook. All rights reserved.
//
import Foundation
import XCTest
@testable import RnCrypto
import IDZSwiftCommonCrypto
class KeyDerivation: XCTestCase {
    let sut = RnCryptoKeyDerivation()
    let utils = RnCryptoUtils()

    func testPbkdf2() throws {
        let password = String("testpassword")
        let salt = String("testsalt")
        let rounds = 2048
        let derivedKeyLength = 64
        let result = sut.pbkdf2(password: password, salt: salt, rounds: rounds, derivedKeyLength: derivedKeyLength)
        
        XCTAssertEqual(utils.bytesToHexString(result), "23c999c8753e1deec3aa8638cd4407f241b0184ad35f7b71be9af5266e6ad31c8025a88e1fe92a03a3815fa35d1b823294f6b4ba79619d52b911f215fe56ae24")
        
    }    
}
