#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RnCrypto, NSObject)



RCT_EXTERN_METHOD(encryptFile:
                  (NSString*)plainFilePath
                  encryptedFilePath:(NSString*)encryptedFilePath
                  hexKey:(NSString*)hexKey
                  hexIv:(NSString*)hexIv
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(decryptFile:
                  (NSString *)encryptedFilePath
                  plainFilePath:(NSString*)plainFilePath
                  hexKey:(NSString*)hexKey
                  hexIv:(NSString*)hexIv
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(pbkdf2:
                  (NSString*) password
                  salt: (NSString*) salt
                  rounds: (nonnull NSNumber*) rounds
                  derivedKeyLength: (nonnull NSNumber*) derivedKeyLength
                  resolve: (RCTPromiseResolveBlock) resolve
                  reject: (RCTPromiseRejectBlock) reject
                  )

RCT_EXTERN_METHOD(sha512:
                  (NSArray*)inputs
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject: (RCTPromiseRejectBlock) reject
                  )

RCT_EXTERN_METHOD(sha256:
                  (NSArray*)inputs
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject: (RCTPromiseRejectBlock) reject
                  )


+ (BOOL)requiresMainQueueSetup
{
    return NO;
}
@end

