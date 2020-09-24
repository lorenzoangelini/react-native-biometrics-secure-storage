#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(BiometricsSecureStorage, NSObject)

RCT_EXTERN_METHOD(authenticate:(NSDictionary*)locale
resolve:(RCTPromiseResolveBlock)resolve
rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encryptAndSaveData:(NSString*)key value:(NSString*)value
resolve:(RCTPromiseResolveBlock)resolve
rejecter:(RCTPromiseRejectBlock)reject
)

RCT_EXTERN_METHOD(loadAndDecryptData:(NSString*)key
resolve:(RCTPromiseResolveBlock)resolve
rejecter:(RCTPromiseRejectBlock)reject
)

RCT_EXTERN_METHOD(isBiometricsAvailable: (RCTPromiseResolveBlock)resolve
rejecter:(RCTPromiseRejectBlock)reject)


RCT_EXTERN_METHOD(reset: (RCTPromiseResolveBlock)resolve
rejecter:(RCTPromiseRejectBlock)reject)


@end
