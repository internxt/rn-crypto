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
    
    init(encryptedFilePath: URL, plainFilePath: URL, hexKey: String, hexIv: String, callback: @escaping (Error?) -> Void) {
        
        self.hexKey = hexKey
        self.hexIv = hexIv
        self.callback = callback
        
        print("Plain file ->", plainFilePath)
        print("Encrypted file ->", encryptedFilePath)
        
        do {
            guard let encryptedFileStream = InputStream(url: encryptedFilePath) else {
                throw RnCryptoError.writeEncryptedFileFailed
            }
            
            guard let plainFileStream = OutputStream(url: plainFilePath, append: true) else {
                throw RnCryptoError.plainFileNotFound
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
                return self.callback(RnCryptoError.plainFileNotFound)
            }
            
            if self.encryptedFileStream == nil {
                return self.callback(RnCryptoError.writeDecryptedFileFailed)
            }
            
            let input = self.encryptedFileStream! as InputStream
            let output = self.plainFileStream! as OutputStream
            
            let cryptStream = StreamCryptor(
                operation: StreamCryptor.Operation.decrypt,
                algorithm: StreamCryptor.Algorithm.aes,
                mode: StreamCryptor.Mode.CTR,
                padding: StreamCryptor.Padding.NoPadding,
                key: utils.hexStringToBytes(self.hexKey)!,
                iv: utils.hexStringToBytes(self.hexIv)!
            )
            
            // Prepare buffers
            let bufferSize = 1024;
            var inputBuffer = Array<UInt8>(repeating:0, count:bufferSize)
            var outputBuffer = Array<UInt8>(repeating:0, count:bufferSize)
            
            // Open streams
            input.open()
            output.open()
            
            var encryptedBytes  : Int = 0;
            while input.hasBytesAvailable {
                // Read the bytes
                let bytesRead = input.read(&inputBuffer, maxLength: inputBuffer.count);
                let status = cryptStream.update(bufferIn: inputBuffer, byteCountIn: bytesRead, bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &encryptedBytes)
                
                // Make sure status is Ok
                assert(status == Status.success)
                if(encryptedBytes > 0) {
                    let bytesOut = output.write(outputBuffer, maxLength: encryptedBytes)
                    assert(bytesOut == Int(encryptedBytes))
                }
                
            }
            
            // Final check
            let status = cryptStream.final(bufferOut: &outputBuffer, byteCapacityOut: outputBuffer.count, byteCountOut: &encryptedBytes)
            
            assert(status == Status.success)
            print("File decrypted ok")
            // Everything ok, close streams and bye bye
            input.close()
            output.close();
            
            self.callback(nil)
        } catch let error {
            print("Error decrypting file", error);
            self.callback(error)
        }
        
    }
}
