#import <Foundation/Foundation.h>

@interface ObjcNaClBoxKey : NSObject
@property(copy,readonly,nonatomic) NSData *keyData;
+ (instancetype)keyWithData:(NSData *)data error:(NSError **)error;
- (id)initWithData:(NSData *)data error:(NSError **)error;
@end

@interface ObjcNaClBoxPublicKey : ObjcNaClBoxKey
@end

@interface ObjcNaClBoxSecretKey : ObjcNaClBoxKey
- (ObjcNaClBoxPublicKey *)publicKey;
@end

@interface ObjcNaClBoxNonce : NSObject
@property(copy,readonly,nonatomic) NSData *nonceData;
+ (instancetype)nonceWithData:(NSData *)data error:(NSError **)error;
- (id)initWithData:(NSData *)data error:(NSError **)error;
@end

@interface ObjcNaClBox : NSObject
+ (instancetype)boxWithSecretKey:(ObjcNaClBoxSecretKey *)secretKey publicKey:(ObjcNaClBoxPublicKey *)publicKey;
- (NSData *)encryptMessage:(NSData *)message withNonce:(ObjcNaClBoxNonce *)nonce error:(NSError **)error;
- (NSData *)decryptCipher:(NSData *)cipher withNonce:(ObjcNaClBoxNonce *)nonce error:(NSError **)error;
@end

extern NSString * const ObjcNaClErrorDomain;
