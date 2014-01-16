#import "tweetnacl-objc.h"
#import "tweetnacl.h"

NSData *ObjcNaClBoxKeypair(NSData **aSecretKey, NSError **anError) {
    NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
    NSMutableData *sk = [NSMutableData dataWithLength:crypto_box_SECRETKEYBYTES];
    int r = crypto_box_keypair([pk mutableBytes], [sk mutableBytes]);
    if (r != 0) {
        if (anError) *anError = [NSError errorWithDomain:@"ObjcNaClErrorDomain" code:r userInfo:nil];
        return nil;
    }
    if (aSecretKey) *aSecretKey = sk;
    return pk;
}
