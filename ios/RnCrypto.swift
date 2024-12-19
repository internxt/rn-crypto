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

        return resolve(utils.bytesToHexString(_:result))
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

        return resolve(utils.bytesToHexString(_:result))
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

    @objc func joinFiles(
        _ inputFiles: [String],
        outputFile: String,
        callback: @escaping RCTResponseSenderBlock
    ) {
        let fileManager = FileManager.default
        let outputURL = URL(fileURLWithPath: outputFile)
        do {
            if fileManager.fileExists(atPath: outputFile) {
                try fileManager.removeItem(at: outputURL)
            }
            fileManager.createFile(atPath: outputFile, contents: nil, attributes: nil)
            guard let outputStream = OutputStream(url: outputURL, append: true) else {
                callback(["Unable to create output stream for: \(outputFile)"])
                return
            }
            outputStream.open()
            defer {
                outputStream.close()
            }
            let bufferSize = 4096
            var buffer = [UInt8](repeating: 0, count: bufferSize)

            for inputFile in inputFiles {
                let inputURL = URL(fileURLWithPath: inputFile)
                guard let inputStream = InputStream(url: inputURL) else {
                    callback(["Unable to create input stream for: \(inputFile)"])
                    return
                }
                inputStream.open()
                defer {
                    inputStream.close()
                    do {
                        try fileManager.removeItem(atPath: inputFile)
                    } catch {
                    }
                }

                while inputStream.hasBytesAvailable {
                    let bytesRead = inputStream.read(&buffer, maxLength: bufferSize)
                    if bytesRead > 0 {
                        let bytesWritten = outputStream.write(buffer, maxLength: bytesRead)
                        if bytesWritten < 0 {
                            callback(["Error writing to output file: \(outputFile)"])
                            return
                        }
                    } else if bytesRead < 0 {
                        callback(["Error reading from file: \(inputFile)"])
                        return
                    }
                }
            }
            callback([NSNull(), "Files successfully combined in: \(outputFile)"])
        } catch let error {
            callback([error.localizedDescription])
        }
    }

    @objc func requiresMainQueueSetup() -> Bool {
        return false
    }
}

