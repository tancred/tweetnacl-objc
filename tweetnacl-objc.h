#import <Foundation/Foundation.h>

@interface CryptoBoxKey : NSObject
@property(copy,readonly,nonatomic) NSData *keyData;
+ (instancetype)keyWithData:(NSData *)data error:(NSError **)error;
- (id)initWithData:(NSData *)data error:(NSError **)error;
@end

@interface CryptoBoxPublicKey : CryptoBoxKey
@end

@interface CryptoBoxSecretKey : CryptoBoxKey
- (CryptoBoxPublicKey *)publicKey;
@end

@interface CryptoBoxNonce : NSObject
@property(copy,readonly,nonatomic) NSData *nonceData;
+ (instancetype)nonceWithData:(NSData *)data error:(NSError **)error;
- (id)initWithData:(NSData *)data error:(NSError **)error;
@end

@interface CryptoBox : NSObject
+ (instancetype)boxWithSecretKey:(CryptoBoxSecretKey *)secretKey publicKey:(CryptoBoxPublicKey *)publicKey;
- (NSData *)encryptMessage:(NSData *)message withNonce:(CryptoBoxNonce *)nonce error:(NSError **)error;
- (NSData *)decryptCipher:(NSData *)cipher withNonce:(CryptoBoxNonce *)nonce error:(NSError **)error;
@end

extern NSString * const ObjcNaClErrorDomain;
