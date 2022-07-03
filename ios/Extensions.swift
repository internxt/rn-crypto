//
//  Extensions.swift
//  RnCrypto
//
//  Created by Robert on 1/7/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import Foundation


// Data extensions
extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return self.map { String(format: format, $0) }.joined()
    }
}
