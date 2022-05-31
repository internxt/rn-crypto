//
//  AES.swift
//  RnCrypto
//
//  Created by Robert on 30/5/22.
//  Copyright © 2022 Facebook. All rights reserved.
//

import Foundation
import IDZSwiftCommonCrypto

class AesCipher {
    var utils = RnCryptoUtils()
    
    public func encrypt(input: InputStream, output:OutputStream, key: [UInt8], iv: [UInt8] ) -> Void {
        
        let cryptStream = StreamCryptor(
            operation: StreamCryptor.Operation.encrypt,
            algorithm: StreamCryptor.Algorithm.aes,
            mode: StreamCryptor.Mode.CTR,
            padding: StreamCryptor.Padding.NoPadding,
            key: key,
            iv: iv
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
        print("File encrypted ok")
        
        // Everything ok, close streams
        input.close()
        output.close();
    }
    
    public func decrypt(input: InputStream, output:OutputStream, key: [UInt8], iv: [UInt8] ) -> Void {
       
        
        let cryptStream = StreamCryptor(
            operation: StreamCryptor.Operation.decrypt,
            algorithm: StreamCryptor.Algorithm.aes,
            mode: StreamCryptor.Mode.CTR,
            padding: StreamCryptor.Padding.NoPadding,
            key:key,
            iv: iv
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
            
            // Make sure status is OK for the cryptStream
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
        
        
        // Close streams
        input.close()
        output.close()
    }
}
