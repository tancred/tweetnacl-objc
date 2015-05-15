#import "tweetnacl-objc.h"
#import "tweetnacl.h"

static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...)  NS_FORMAT_FUNCTION(2, 3);


@interface ObjcNaClBoxKey ()
@property(copy,nonatomic) NSData *keyData;
@end

@interface ObjcNaClBoxSecretKey ()
@property(strong,nonatomic) ObjcNaClBoxPublicKey *publicKey;
@end


@implementation ObjcNaClBoxKey

+ (instancetype)keyWithData:(NSData *)someData error:(NSError **)anError {
    return [[self alloc] initWithData:someData error:anError];
}

- (id)initWithData:(NSData *)someData error:(NSError **)anError {
    if (!(self = [super init])) return nil;
    self.keyData = someData;
    return self;
}

@end


@implementation ObjcNaClBoxPublicKey

- (id)initWithData:(NSData *)someData error:(NSError **)anError {
    if (!(self = [super initWithData:someData error:anError])) return nil;
    if ([self.keyData length] != crypto_box_PUBLICKEYBYTES) {
        if (anError) *anError = CreateError(2, @"incorrect public-key length");
        return nil;
    }
    return self;
}

@end


@implementation ObjcNaClBoxSecretKey

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
    self.publicKey = [[ObjcNaClBoxPublicKey alloc] initWithData:pk error:NULL];
    return self;
}

- (ObjcNaClBoxPublicKey *)publicKey {
    if (!_publicKey) {
        NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
        crypto_scalarmult_base([pk mutableBytes],[self.keyData bytes]);
        self.publicKey = [ObjcNaClBoxPublicKey keyWithData:pk error:NULL];
    }
    return _publicKey;
}

@end


@interface ObjcNaClBoxNonce ()
@property(copy,nonatomic) NSData *nonceData;
@end

@implementation ObjcNaClBoxNonce

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


@interface ObjcNaClBox ()
@property(copy) NSData *k;
@end

@implementation ObjcNaClBox
+ (instancetype)boxWithSecretKey:(ObjcNaClBoxSecretKey *)aSecretKey publicKey:(ObjcNaClBoxPublicKey *)aPublicKey error:(NSError **)anError {
    return [[self alloc] initWithSecretKey:aSecretKey publicKey:aPublicKey error:anError];
}

- (id)initWithSecretKey:(ObjcNaClBoxSecretKey *)aSecretKey publicKey:(ObjcNaClBoxPublicKey *)aPublicKey error:(NSError **)anError {
    if (!(self = [super init])) return nil;

    if (![aSecretKey isKindOfClass:[ObjcNaClBoxSecretKey class]]) {
        if (anError) *anError = CreateError(0, @"invalid secret key");
        return nil;
    }

    if (![aPublicKey isKindOfClass:[ObjcNaClBoxPublicKey class]]) {
        if (anError) *anError = CreateError(0, @"invalid public key");
        return nil;
    }

    unsigned char k[crypto_box_BEFORENMBYTES];
    crypto_box_beforenm(k, [aPublicKey.keyData bytes], [aSecretKey.keyData bytes]);
    self.k = [NSData dataWithBytes:k length:crypto_box_BEFORENMBYTES];

    return self;
}

- (NSData *)encryptMessage:(NSData *)aMessage withNonce:(ObjcNaClBoxNonce *)aNonce error:(NSError **)anError {
    if (![aMessage isKindOfClass:[NSData class]]) {
        if (anError) *anError = CreateError(0, @"invalid message");
        return nil;
    }
    if (![aNonce isKindOfClass:[ObjcNaClBoxNonce class]]) {
        if (anError) *anError = CreateError(0, @"invalid nonce");
        return nil;
    }

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

- (NSData *)decryptCipher:(NSData *)aCipher withNonce:(ObjcNaClBoxNonce *)aNonce error:(NSError **)anError {
    if (![aCipher isKindOfClass:[NSData class]]) [NSException raise:NSInvalidArgumentException format:@"invalid cipher"];
    if (![aNonce isKindOfClass:[ObjcNaClBoxNonce class]]) [NSException raise:NSInvalidArgumentException format:@"invalid nonce"];

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
