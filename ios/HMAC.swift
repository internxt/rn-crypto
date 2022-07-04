//
//  Hashes.swift
//  RnCrypto
//
//  Created by Robert on 28/6/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import Foundation
import CryptoKit

enum HashInput {
    case message ([UInt8])
    case messages (Array<[UInt8]>)
}

@available(iOS 13.0, *)
class RnCryptoHMAC {

    
    func sha512(inputs: Array<[UInt8]>) -> [UInt8] {
        
        var hash = SHA512.init()
        for (_, input) in inputs.enumerated() {
            hash.update(data: input)
        }
        
        let digest = hash.finalize()
        var result = [UInt8]()
        digest.withUnsafeBytes {bytes in
            result.append(contentsOf: bytes)
        }
        
        return result
    }
    
    func sha256(inputs: Array<[UInt8]>) -> [UInt8] {
        
        var hash = SHA256.init()
        for (_, input) in inputs.enumerated() {
            hash.update(data: input)
        }
        
        let digest = hash.finalize()
        var result = [UInt8]()
        digest.withUnsafeBytes {bytes in
            result.append(contentsOf: bytes)
        }
        
        return result
    }
    
   
    
    
}
