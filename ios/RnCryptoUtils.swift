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
}


enum RnCryptoError: Error {
    case badIv
    case badKey
    case decryptedFile
    case encryptedFile
    case encryptionFailed
    case plainFile
}
