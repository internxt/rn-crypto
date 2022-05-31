//
//  1rr.swift
//  RnCryptoTests
//
//  Created by Robert on 30/5/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import XCTest
@testable import RnCrypto

class AesCipherTests: XCTestCase {
    let sut = AesCipher()
    let utils = RnCryptoUtils()
    func testEncrypt() throws {
        let destination = NSTemporaryDirectory() + "/encrypt.enc"
        let inputStream = InputStream.init(data: "Hi im a string".data(using: .utf8)!)
        let outputStream = OutputStream(url: URL(fileURLWithPath: destination), append: true)
        
        
        let hexKey = "570ae1d9a9e44af02ca9215591692627328aa62d068e50d285a01cfb0c811775"
        let hexIv = "2948404D63516654"
        
        self.sut.encrypt(
            input: inputStream,
            output: outputStream!,
            key: self.utils.hexStringToBytes(hexKey)!,
            iv:  self.utils.hexStringToBytes(hexIv)!
        )
        
        do {
            let result = try String(contentsOf: URL(fileURLWithPath:destination), encoding: .utf8)
            
            XCTAssertEqual(result, "123")
            
        } catch {
            fatalError("Cannot get encrypted file content, failing test")
        }
        
        
    
    }

}
