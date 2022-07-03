import Foundation
import IDZSwiftCommonCrypto



@objc(RnCrypto)
class RnCrypto: NSObject {
    var encryptionQueue = OperationQueue()
    var decryptionQueue = OperationQueue()
    var utils = RnCryptoUtils()
    var HMAC = RnCryptoHMAC()
    
    func load() {
        encryptionQueue.name = "EncryptionQueue"
        decryptionQueue.name = "DecryptionQueue"
    }
    
    
    @objc func sha256(
        _ inputs: NSArray,
        resolve: RCTPromiseResolveBlock
    ) {
        let byteInputs = inputs.map {
            guard let input = $0 as? String else {return []}
            
            return utils.hexStringToBytes(input)
        } as Array<[UInt8]>
        
        let result = HMAC.sha256(inputs: byteInputs)
        
        return resolve(result.description.hex)
    }
    
    @objc func sha512(
        _ inputs: NSArray,
        resolve: RCTPromiseResolveBlock
    ) {
        let byteInputs = inputs.map {
            guard let input = $0 as Any as? String else {
                return []
            }
            return utils.hexStringToBytes(input)
        } as Array<[UInt8]>
        
        let result = HMAC.sha512(inputs: byteInputs)
        
        return resolve(result.description.hex)
    }
    
    @objc func encryptFile(
        _ plainFilePath: String,
        encryptedFilePath: String,
        hexKey: String,
        hexIv: String,
        callback: @escaping RCTResponseSenderBlock
    ) -> Void {
        
        
        let operation = EncryptFileOperation(
            plainFilePath: URL(fileURLWithPath: plainFilePath),
            encryptedFilePath: URL(fileURLWithPath: encryptedFilePath),
            hexKey:hexKey,
            hexIv: hexIv,
            callback: {(error: Error?) in
                if error != nil {
                    callback([error!, NSNull()])
                } else {
                    callback([NSNull(), NSNull()])
                }
            }
        )

        self.encryptionQueue.addOperation(operation)
        
    }
    
    
    @objc func decryptFile(
        _ encryptedFilePath: String,
        plainFilePath: String,
        hexKey: String,
        hexIv: String,
        callback: @escaping RCTResponseSenderBlock
    ) -> Void {
        
        
        let operation = DecryptFileOperation(
            encryptedFilePath: URL(fileURLWithPath: encryptedFilePath),
            plainFilePath: URL(fileURLWithPath: plainFilePath),
            hexKey:hexKey,
            hexIv: hexIv,
            callback: {(error: Error?) in
                if error != nil {
                    callback([error?.localizedDescription ?? "Unknown error", NSNull()])
                } else {
                    callback([NSNull(), NSNull()])
                }
            }
        )

        self.decryptionQueue.addOperation(operation)
    }


    @objc func requiresMainQueueSetup() -> Bool {
        return false
    }
}
