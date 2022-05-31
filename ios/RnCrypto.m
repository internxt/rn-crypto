#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RnCrypto, NSObject)



RCT_EXTERN_METHOD(encryptFile:
                  (NSString*)plainFilePath
                  encryptedFilePath:(NSString*)encryptedFilePath
                  hexKey:(NSString*)hexKey
                  hexIv:(NSString*)hexIv
                  callback:(RCTResponseSenderBlock)callback)

RCT_EXTERN_METHOD(decryptFile:
                  (NSString*)encryptedFilePath
                  plainFilePath:(NSString*)plainFilePath
                  hexKey:(NSString*)hexKey
                  hexIv:(NSString*)hexIv
                  callback:(RCTResponseSenderBlock)callback)

@end
