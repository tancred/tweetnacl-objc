#import "tweetnacl-objc.h"
#import "tweetnacl.h"

static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...)  NS_FORMAT_FUNCTION(2, 3);


@interface CryptoBoxKey ()
@property(copy,nonatomic) NSData *keyData;
@end

@interface CryptoBoxSecretKey ()
@property(strong,nonatomic) CryptoBoxPublicKey *publicKey;
@end


@implementation CryptoBoxKey

+ (instancetype)keyWithData:(NSData *)someData error:(NSError **)anError {
    return [[self alloc] initWithData:someData error:anError];
}

- (id)initWithData:(NSData *)someData error:(NSError **)anError {
    if (!(self = [super init])) return nil;
    self.keyData = someData;
    return self;
}

@end


@implementation CryptoBoxPublicKey

- (id)initWithData:(NSData *)someData error:(NSError **)anError {
    if (!(self = [super initWithData:someData error:anError])) return nil;
    if ([self.keyData length] != crypto_box_PUBLICKEYBYTES) {
        if (anError) *anError = CreateError(2, @"incorrect public-key length");
        return nil;
    }
    return self;
}

@end


@implementation CryptoBoxSecretKey

- (id)initWithData:(NSData *)someData error:(NSError **)anError {
    if (!(self = [super initWithData:someData error:anError])) return nil;
    if ([self.keyData length] != crypto_box_SECRETKEYBYTES) {
        if (anError) *anError = CreateError(3, @"incorrect secret-key length");
        return nil;
    }
    return self;
}

- (id)init {
    if (!(self = [super init])) return nil;
    NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
    NSMutableData *sk = [NSMutableData dataWithLength:crypto_box_SECRETKEYBYTES];
    crypto_box_keypair([pk mutableBytes], [sk mutableBytes]);
    self.keyData = sk;
    self.publicKey = [[CryptoBoxPublicKey alloc] initWithData:pk error:NULL];
    return self;
}

- (CryptoBoxPublicKey *)publicKey {
    if (!_publicKey) {
        NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
        crypto_scalarmult_base([pk mutableBytes],[self.keyData bytes]);
        self.publicKey = [CryptoBoxPublicKey keyWithData:pk error:NULL];
    }
    return _publicKey;
}

@end


@interface CryptoBoxNonce ()
@property(copy,nonatomic) NSData *nonceData;
@end

@implementation CryptoBoxNonce

+ (instancetype)nonceWithData:(NSData *)someData error:(NSError **)anError {
    return [[self alloc] initWithData:someData error:anError];
}

- (id)initWithData:(NSData *)someData error:(NSError **)anError {
    if (!(self = [super init])) return nil;
    if ([someData length] != crypto_box_NONCEBYTES) {
        if (anError) *anError = CreateError(1, @"incorrect nonce length");
        return nil;
    }
    self.nonceData = someData;
    return self;
}

@end


@interface CryptoBox ()
@property(copy) NSData *k;
@end

@implementation CryptoBox
+ (instancetype)boxWithSecretKey:(CryptoBoxSecretKey *)aSecretKey publicKey:(CryptoBoxPublicKey *)aPublicKey {
    return [[self alloc] initWithSecretKey:aSecretKey publicKey:aPublicKey];
}

- (id)initWithSecretKey:(CryptoBoxSecretKey *)aSecretKey publicKey:(CryptoBoxPublicKey *)aPublicKey {
    if (!(self = [super init])) return nil;
    if (![aSecretKey isKindOfClass:[CryptoBoxSecretKey class]]) [NSException raise:NSInvalidArgumentException format:@"invalid secret-key"];
    if (![aPublicKey isKindOfClass:[CryptoBoxPublicKey class]]) [NSException raise:NSInvalidArgumentException format:@"invalid public-key"];

    unsigned char k[crypto_box_BEFORENMBYTES];
    crypto_box_beforenm(k, [aPublicKey.keyData bytes], [aSecretKey.keyData bytes]);
    self.k = [NSData dataWithBytes:k length:crypto_box_BEFORENMBYTES];

    return self;
}

- (NSData *)encryptMessage:(NSData *)aMessage withNonce:(CryptoBoxNonce *)aNonce error:(NSError **)anError {
    if (![aMessage isKindOfClass:[NSData class]]) [NSException raise:NSInvalidArgumentException format:@"invalid message"];
    if (![aNonce isKindOfClass:[CryptoBoxNonce class]]) [NSException raise:NSInvalidArgumentException format:@"invalid nonce"];

    NSMutableData *m = [NSMutableData dataWithLength:crypto_box_ZEROBYTES];
    [m appendData:aMessage];

    NSMutableData *c = [NSMutableData dataWithLength:[m length]];
    int r = crypto_box_afternm([c mutableBytes], [m bytes], [m length], [aNonce.nonceData bytes], [self.k bytes]);
    if (r != 0) {
        if (anError) *anError = CreateError(r, @"xxx: crypto_box failed");
        return nil;
    }

    return [c subdataWithRange:NSMakeRange(crypto_box_BOXZEROBYTES, [c length] - crypto_box_BOXZEROBYTES)];
}

- (NSData *)decryptCipher:(NSData *)aCipher withNonce:(CryptoBoxNonce *)aNonce error:(NSError **)anError {
    if (![aCipher isKindOfClass:[NSData class]]) [NSException raise:NSInvalidArgumentException format:@"invalid cipher"];
    if (![aNonce isKindOfClass:[CryptoBoxNonce class]]) [NSException raise:NSInvalidArgumentException format:@"invalid nonce"];

    NSMutableData *c = [NSMutableData dataWithLength:crypto_box_BOXZEROBYTES];
    [c appendData:aCipher];

    NSMutableData *m = [NSMutableData dataWithLength:[c length]];
    int r = crypto_box_open_afternm([m mutableBytes], [c bytes], [c length], [aNonce.nonceData bytes], [self.k bytes]);
    if (r != 0) {
        if (anError) *anError = CreateError(r, @"ciphertext verification failed");
        return nil;
    }

    return [m subdataWithRange:NSMakeRange(crypto_box_ZEROBYTES, [m length] - crypto_box_ZEROBYTES)];
}

@end


static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...) {
    va_list args;
    va_start(args, descriptionFormat);
    NSString *s = [[NSString alloc] initWithFormat:descriptionFormat arguments:args];
    va_end(args);
    return [NSError errorWithDomain:ObjcNaClErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey:s}];
}

NSString * const ObjcNaClErrorDomain = @"ObjcNaClErrorDomain";
