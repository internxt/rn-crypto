//
//  EncryptFileOperation.swift
//  rn-crypto
//
//  Created by Robert on 27/5/22.
//

import Foundation
import IDZSwiftCommonCrypto

class EncryptFileOperation : Operation {
    
    var plainFileStream: InputStream?
    var encryptedFileStream: OutputStream?
    var hexIv: String
    var hexKey: String
    
    var callback: (Error?) -> Void
    
    private var utils = RnCryptoUtils()
    private var aes = AesCipher()
    
    init(plainFilePath: URL, encryptedFilePath: URL, hexKey: String, hexIv: String, callback: @escaping (Error?) -> Void) {
        
        self.hexKey = hexKey
        self.hexIv = hexIv
        self.callback = callback
        
        do {
            guard let plainFileStream = InputStream(url: plainFilePath) else {
                throw RnCryptoError.plainFile
            }
            
            guard let encryptedFileStream = OutputStream(url: encryptedFilePath, append: true) else {
                throw RnCryptoError.encryptedFile
            }
            
            self.plainFileStream = plainFileStream
            self.encryptedFileStream = encryptedFileStream
        } catch let error {
            print("Error preparing encrypt streams this will fail on Operation main() call", error);
        }
        
    }
    
    override func main() {
        
        do {
            
            if self.plainFileStream == nil {
                return self.callback(RnCryptoError.plainFile)
            }
            
            if self.encryptedFileStream == nil {
                return self.callback(RnCryptoError.encryptedFile)
            }
            
            guard let iv = self.utils.hexStringToBytes(self.hexIv) else {
                throw RnCryptoError.badIv
            }
            
            guard let key = self.utils.hexStringToBytes(self.hexKey) else {
                throw RnCryptoError.badKey
            }
            
            
            self.aes.encrypt(
                input: self.plainFileStream!,
                output: self.encryptedFileStream!,
                key: key,
                iv: iv,
                callback: {(error, status) in
                    self.callback(error)
                }
            )
        } catch let error {
            print("Error encrypting file", error);
            self.callback(error)
        }
        
    }
}
