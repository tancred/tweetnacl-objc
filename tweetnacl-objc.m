#import "tweetnacl-objc.h"
#import "tweetnacl.h"

static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...)  NS_FORMAT_FUNCTION(2, 3);
static BOOL IsValidNonceAndKeys(NSData *n, NSData *pk, NSData *sk, NSError **anError);
static BOOL IsValidNonce(NSData *n, NSError **anError);
static BOOL IsValidPublicKey(NSData *n, NSError **anError);
static BOOL IsValidSecretKey(NSData *n, NSError **anError);

NSData *ObjcNaClBoxKeypair(NSData **aSecretKey, NSError **anError) {
    NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
    NSMutableData *sk = [NSMutableData dataWithLength:crypto_box_SECRETKEYBYTES];
    int r = crypto_box_keypair([pk mutableBytes], [sk mutableBytes]);
    if (r != 0) {
        if (anError) *anError = [NSError errorWithDomain:ObjcNaClErrorDomain code:r userInfo:nil];
        return nil;
    }
    if (aSecretKey) *aSecretKey = sk;
    return pk;
}

NSData *ObjcNaClBox(NSData *m, NSData *n, NSData *pk, NSData *sk, NSError **anError) {
    if (!IsValidNonceAndKeys(n, pk, sk, anError)) return nil;

    NSMutableData *mm = [NSMutableData dataWithLength:crypto_box_ZEROBYTES];
    [mm appendData:m];

    NSMutableData *c = [NSMutableData dataWithLength:[mm length]];
    int r = crypto_box([c mutableBytes], [mm bytes], [mm length], [n bytes], [pk bytes], [sk bytes]);
    if (r != 0) {
        if (anError) *anError = [NSError errorWithDomain:ObjcNaClErrorDomain code:r userInfo:nil];
        return nil;
    }

    return [c subdataWithRange:NSMakeRange(crypto_box_BOXZEROBYTES, [c length] - crypto_box_BOXZEROBYTES)];
}

NSData *ObjcNaClBoxOpen(NSData *c, NSData *n, NSData *pk, NSData *sk, NSError **anError) {
    if (!IsValidNonceAndKeys(n, pk, sk, anError)) return nil;

    NSMutableData *cc = [NSMutableData dataWithLength:crypto_box_BOXZEROBYTES];
    [cc appendData:c];

    NSMutableData *m = [NSMutableData dataWithLength:[cc length]];
    int r = crypto_box_open([m mutableBytes], [cc bytes], [cc length], [n bytes], [pk bytes], [sk bytes]);
    if (r != 0) {
        if (anError) *anError = CreateError(r, @"ciphertext verification failed");
        return nil;
    }

    return [m subdataWithRange:NSMakeRange(crypto_box_ZEROBYTES, [m length] - crypto_box_ZEROBYTES)];
}

static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...) {
    va_list args;
    va_start(args, descriptionFormat);
    NSString *s = [[NSString alloc] initWithFormat:descriptionFormat arguments:args];
    va_end(args);
    return [NSError errorWithDomain:ObjcNaClErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey:s}];
}

static BOOL IsValidNonceAndKeys(NSData *n, NSData *pk, NSData *sk, NSError **anError) {
    if (!IsValidNonce(n, anError)) return NO;
    if (!IsValidPublicKey(pk, anError)) return NO;
    if (!IsValidSecretKey(sk, anError)) return NO;
    return YES;
}

static BOOL IsValidNonce(NSData *n, NSError **anError) {
    if ([n length] != crypto_box_NONCEBYTES) { if (anError) *anError = CreateError(1, @"incorrect nonce length"); return NO; }
    return YES;
}

static BOOL IsValidPublicKey(NSData *pk, NSError **anError) {
    if ([pk length] != crypto_box_PUBLICKEYBYTES) { if (anError) *anError = CreateError(2, @"incorrect public-key length"); return NO; }
    return YES;
}

static BOOL IsValidSecretKey(NSData *sk, NSError **anError) {
    if ([sk length] != crypto_box_SECRETKEYBYTES) { if (anError) *anError = CreateError(3, @"incorrect secret-key length"); return NO; }
    return YES;
}

NSString * const ObjcNaClErrorDomain = @"ObjcNaClErrorDomain";
