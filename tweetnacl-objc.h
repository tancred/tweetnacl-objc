#import <Foundation/Foundation.h>

NSData *ObjcNaClBoxKeypair(NSData **sk, NSError **error);

NSData *ObjcNaClBox(NSData *m, NSData *n, NSData *pk, NSData *sk, NSError **error);
NSData *ObjcNaClBoxOpen(NSData *c, NSData *n, NSData *pk, NSData *sk, NSError **error);

BOOL ObjcNaClBoxBeforeNM(NSData **k, NSData *pk, NSData *sk, NSError **error);
NSData *ObjcNaClBoxAfterNM(NSData *m, NSData *n, NSData *k, NSError **error);

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
- (NSData *)encryptMessage:(NSData *)message withNonce:(NSData *)nonce error:(NSError **)error;
@end

extern NSString * const ObjcNaClErrorDomain;

/*
@interface ObjcNaClBox : NSObject
@property(copy) NSData *k;
- (id)initWithPublicKey:(NSData *)pk secretKey:(NSData *)sk error:(NSError *)error;
- (BOOL)precomputeWithPublicKey:(NSData *)pk secrectKey:(NSData *)sk error:(NSError *)error;
- (NSData *)boxMessage:(NSData *)m nonce:(NSData *)n error:(NSError **)error;
- (NSData *)openMessage:(NSData *)m nonce:(NSData *)n error:(NSError **)error;
@end

// or without NSError?

NSData *ObjcNaClBoxKeypair(NSData **sk);

NSData *ObjcNaClBox(NSData *m, NSData *n, NSData *pk, NSData *sk);
NSData *ObjcNaClBoxOpen(NSData *c, NSData *n, NSData *pk, NSData *sk);

BOOL ObjcNaClBoxBeforeNM(NSData **k, NSData *pk, NSData *sk);
NSData *ObjcNaClBoxAfterNM(NSData *m, NSData *n, NSData *k);

@interface ObjcNaClBox : NSObject
@property(copy) NSData *k;
- (id)initWithPublicKey:(NSData *)pk secretKey:(NSData *)sk;
- (BOOL)precomputeWithPublicKey:(NSData *)pk secrectKey:(NSData *)sk;
- (NSData *)boxMessage:(NSData *)m nonce:(NSData *)n;
- (NSData *)openMessage:(NSData *)m nonce:(NSData *)n;
@end

*/
