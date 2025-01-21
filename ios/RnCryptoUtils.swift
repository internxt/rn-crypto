//
//  RnCryptoUtils.swift
//  rn-crypto
//
//  Created by Robert on 27/5/22.
//

import Foundation
import IDZSwiftCommonCrypto

class RnCryptoUtils {
    public func hexStringToBytes(_ hexString: String) -> [UInt8] {
        return arrayFrom(hexString: hexString)
    }

    public func bytesToHexString(_ bytes: [UInt8]) -> String {
        let format = "%02hhx"
        return bytes.map { String(format: format, $0) }.joined()
    }
}

extension StringProtocol {
    var hex: [UInt8] {
        var startIndex = self.startIndex
        return (0..<count / 2).compactMap { _ in
            let endIndex = index(after: startIndex)
            defer { startIndex = index(after: endIndex) }
            return UInt8(self[startIndex...endIndex], radix: 16)
        }
    }
}

enum RnCryptoError: Error {
    case badIv
    case badKey
    case decryptedFile
    case encryptedFile
    case encryptionFailed
    case plainFile
    case fileCreationFailed
    case writeFailed
    case outputStreams
}
