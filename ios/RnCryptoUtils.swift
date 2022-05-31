//
//  RnCryptoUtils.swift
//  rn-crypto
//
//  Created by Robert on 27/5/22.
//

import Foundation

class RnCryptoUtils {
    public func hexStringToBytes(_ string: String) -> [UInt8]? {
        let length = string.count
        if length & 1 != 0 {
            return nil
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length/2)
        var index = string.startIndex
        for _ in 0..<length/2 {
            let nextIndex = string.index(index, offsetBy: 2)
            if let b = UInt8(string[index..<nextIndex], radix: 16) {
                bytes.append(b)
            } else {
                return nil
            }
            index = nextIndex
        }
        return bytes
    }
}


enum RnCryptoError: Error {
    case badIv
    case badKey
    case decryptedFile
    case encryptedFile
    case encryptionFailed
    case plainFile
}
