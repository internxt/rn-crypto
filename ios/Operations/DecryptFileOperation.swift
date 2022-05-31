//
//  DecryptFileOperation.swift
//  rn-crypto
//
//  Created by Robert on 27/5/22.
//

import Foundation
import IDZSwiftCommonCrypto

class DecryptFileOperation : Operation {
    
    var plainFileStream: OutputStream?
    var encryptedFileStream: InputStream?
    var hexIv: String
    var hexKey: String
    var callback: (Error?) -> Void
    
    private var utils = RnCryptoUtils()
    private var aes = AesCipher()
    init(encryptedFilePath: URL, plainFilePath: URL, hexKey: String, hexIv: String, callback: @escaping (Error?) -> Void) {
        
        self.hexKey = hexKey
        self.hexIv = hexIv
        self.callback = callback
        
        do {
            guard let encryptedFileStream = InputStream(url: encryptedFilePath) else {
                throw RnCryptoError.decryptedFile
            }
            
            guard let plainFileStream = OutputStream(url: plainFilePath, append: true) else {
                throw RnCryptoError.plainFile
            }
            
            self.plainFileStream = plainFileStream
            self.encryptedFileStream = encryptedFileStream
        } catch let error {
            print("Error preparing decrypt streams this will fail on Operation main() call", error);
        }
        
    }
    
    override func main() {
        
        do {
            
            if self.plainFileStream == nil {
                return self.callback(RnCryptoError.plainFile)
            }
            
            if self.encryptedFileStream == nil {
                return self.callback(RnCryptoError.decryptedFile)
            }
            
            self.aes.decrypt(
                input:  self.encryptedFileStream!,
                output:self.plainFileStream!,
                key: self.utils.hexStringToBytes(self.hexKey)!,
                iv: self.utils.hexStringToBytes(self.hexIv)!,
                callback: {(error, status) in
                    self.callback(error)
                }
            )
            
        } catch let error {
            print("Error decrypting file", error);
            self.callback(error)
        }
        
    }
}
