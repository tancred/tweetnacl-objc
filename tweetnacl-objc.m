#import "tweetnacl-objc.h"
#import "tweetnacl.h"

static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...)  NS_FORMAT_FUNCTION(2, 3);

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
    if ([n length] != crypto_box_NONCEBYTES) { if (anError) *anError = CreateError(1, @"incorrect nonce length"); return nil; }

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

static NSError *CreateError(NSInteger code, NSString *descriptionFormat, ...) {
    va_list args;
    va_start(args, descriptionFormat);
    NSString *s = [[NSString alloc] initWithFormat:descriptionFormat arguments:args];
    va_end(args);
    return [NSError errorWithDomain:ObjcNaClErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey:s}];
}

NSString * const ObjcNaClErrorDomain = @"ObjcNaClErrorDomain";
