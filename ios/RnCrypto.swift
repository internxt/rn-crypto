import Foundation
import IDZSwiftCommonCrypto



@objc(RnCrypto)
class RnCrypto: NSObject {
    var encryptionQueue = OperationQueue()
    var decryptionQueue = OperationQueue()
    
    func load() {
        encryptionQueue.name = "EncryptionQueue"
        decryptionQueue.name = "DecryptionQueue"
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
                    callback([error, NSNull()])
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
                    callback([error?.localizedDescription, NSNull()])
                } else {
                    callback([NSNull(), NSNull()])
                }
            }
        )

        self.decryptionQueue.addOperation(operation)
        
    }
}
