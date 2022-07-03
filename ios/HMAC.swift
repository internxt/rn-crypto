//
//  Hashes.swift
//  RnCrypto
//
//  Created by Robert on 28/6/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto


enum HashInput {
    case message ([UInt8])
    case messages (Array<[UInt8]>)
}
class RnCryptoHMAC {
    func sha256(inputs: Array<[UInt8]> ) -> [UInt8] {
        return toAlgorithm(inputs: inputs, algorithm: HMAC.Algorithm.sha256)
    }
    
    func sha512(inputs: Array<[UInt8]>) -> [UInt8] {
        return toAlgorithm(inputs: inputs, algorithm: HMAC.Algorithm.sha512)
    }
    
    private func toAlgorithm(inputs: Array<[UInt8]>, algorithm: HMAC.Algorithm) -> [UInt8] {
        let hash = HMAC(algorithm: algorithm, key: inputs[0])
        for (index, message) in inputs.enumerated() {
            if index > 0 {
                _ = hash.update(message)
            }
        }
        return hash.final()
    }
}
