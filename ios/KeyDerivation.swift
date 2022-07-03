//
//  KeyDerivation.swift
//  RnCrypto
//
//  Created by Robert on 1/7/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto
class RnCryptoKeyDerivation {
    func pbkdf2(password: String, salt: String, rounds: Int, derivedKeyLength: Int) -> [UInt8] {
        return PBKDF.deriveKey(password: password, salt: salt, prf: PBKDF.PseudoRandomAlgorithm.sha512, rounds: uint(rounds), derivedKeyLength: UInt(derivedKeyLength))
    }
}
