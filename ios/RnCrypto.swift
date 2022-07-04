import Foundation
import IDZSwiftCommonCrypto



@available(iOS 13.0, *)
@objc(RnCrypto)
class RnCrypto: NSObject {
    var encryptionQueue = OperationQueue()
    var decryptionQueue = OperationQueue()
    var utils = RnCryptoUtils()
    var HMAC = RnCryptoHMAC()
    var keyDerivation = RnCryptoKeyDerivation()

    func load() {
        encryptionQueue.name = "EncryptionQueue"
        decryptionQueue.name = "DecryptionQueue"
    }
    
    
    @objc func sha256(
        _ inputs: NSArray,
        resolve: RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        let byteInputs = inputs.map {
            guard let input = $0 as? String else {return []}

            return utils.hexStringToBytes(input)
        } as Array<[UInt8]>

        let result = HMAC.sha256(inputs: byteInputs)

        return resolve(result.description.hex)
    }
    
    @available(iOS 13.0, *)
    @objc func sha512(
        _ inputs: NSArray,
        resolve: RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
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
    
    @objc func pbkdf2(
        _ password: String,
        salt: String,
        rounds: NSNumber,
        derivedKeyLength: NSNumber,
        resolve: RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        let result = keyDerivation.pbkdf2(
            password: password,
            salt: salt,
            rounds: rounds.intValue,
            derivedKeyLength: derivedKeyLength.intValue
        )
        return resolve(utils.bytesToHexString(_:result))
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

