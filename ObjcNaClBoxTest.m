#import <SenTestingKit/SenTestingKit.h>
#import "tweetnacl-objc.h"
#import "tweetnacl.h"
#import "NSData+Hex.h"

#define AssertError(actualError, expectedCode, expectedDomain, expectedDesc) \
do { \
    STAssertNotNil((actualError), nil, nil); \
    if (!(actualError)) break; \
    STAssertEquals([(actualError) code], (NSInteger)(expectedCode), @"code"); \
    STAssertEqualObjects([(actualError) domain], expectedDomain, @"domain"); \
    STAssertEqualObjects([[(actualError) userInfo] objectForKey:NSLocalizedDescriptionKey], (expectedDesc), nil); \
} while(0)


static NSData *STR2DATA(const char *x);
static NSData *HEX2DATA(const char *x);


@interface ObjcNaClBoxTest : SenTestCase
@property(strong) ObjcNaClBoxSecretKey *alicesKey;
@property(strong) ObjcNaClBoxSecretKey *bobsKey;
@property(strong) ObjcNaClBoxNonce *nonce;
@property(strong) NSData *aliceMessage;
@property(strong) NSData *aliceCipher;
@end

@interface ObjcNaClBoxKeyTest : SenTestCase
@end

@interface ObjcNaClBoxNonceTest : SenTestCase
@end


@implementation ObjcNaClBoxTest
@synthesize alicesKey, bobsKey, nonce, aliceMessage, aliceCipher;

- (void)setUp {
    alicesKey    = [ObjcNaClBoxSecretKey keyWithData:HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303") error:NULL];
    bobsKey      = [ObjcNaClBoxSecretKey keyWithData:HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404") error:NULL];
    nonce        = [ObjcNaClBoxNonce nonceWithData:HEX2DATA("434343434343434343434343434343434343434343434343") error:NULL];
    aliceMessage = STR2DATA("Hello, World!");
    aliceCipher  = HEX2DATA("c808d6d80af8c02b190890bbf68387a35ea0429e02b3d295f7686e4585");
}

- (void)testEncrypt {
    ObjcNaClBox *alicesBox = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:[bobsKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *c = [alicesBox encryptMessage:aliceMessage withNonce:nonce error:&error];
    STAssertEqualObjects(c, aliceCipher, @"cipher");
    STAssertEqualObjects(error, nil, nil);
}

- (void)testBoxFailsOnInvalidKeyArguments {
    NSError *error = nil;
    ObjcNaClBox *box = [ObjcNaClBox boxWithSecretKey:nil publicKey:nil error:&error];
    STAssertNil(box, nil, @"box");
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid secret key");

    error = nil;
    box = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:nil error:&error];
    STAssertNil(box, nil, @"box");
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid public key");
}

- (void)testEncryptRaisesOnInvalidEncryptArguments {
    ObjcNaClBox *alicesBox = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:[bobsKey publicKey] error:NULL];
    STAssertThrowsSpecificNamed([alicesBox encryptMessage:nil withNonce:nonce error:NULL], NSException, NSInvalidArgumentException, @"message");
    STAssertThrowsSpecificNamed([alicesBox encryptMessage:aliceMessage withNonce:nil error:NULL], NSException, NSInvalidArgumentException, @"nonce");
}

- (void)testDecrypt {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    STAssertEqualObjects(m, aliceMessage, @"message"); //48656c6c6f2c20576f726c6421
    STAssertEqualObjects(error, nil, nil);
}

- (void)testDecryptRaisesOnInvalidEncryptArguments {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    STAssertThrowsSpecificNamed([bobsBox decryptCipher:nil withNonce:nonce error:NULL], NSException, NSInvalidArgumentException, @"message");
    STAssertThrowsSpecificNamed([bobsBox decryptCipher:aliceCipher withNonce:nil error:NULL], NSException, NSInvalidArgumentException, @"nonce");
}

- (void)testBoxOpenFailsWithBadPublicKey {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[bobsKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    STAssertNil(m, nil, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

- (void)testBoxOpenFailsWithBadSecretKey {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    STAssertNil(m, nil, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

- (void)testBoxOpenFailsWithBadNonce {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    nonce = [ObjcNaClBoxNonce nonceWithData:HEX2DATA("434343434343434343434343434343434343434343434344") error:NULL];
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    STAssertNil(m, nil, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

- (void)testBoxOpenFailsWithChangedCipher {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    aliceCipher  = HEX2DATA("bb9fa648e55b759aeaf62785214fedf4d3d60a6bfc40661a7ec0cc4494");
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    STAssertNil(m, nil, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

@end


@implementation ObjcNaClBoxKeyTest

- (void)testPublicKey {
    NSData *data = HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22");
    ObjcNaClBoxPublicKey *pk = [ObjcNaClBoxPublicKey keyWithData:data error:NULL];
    STAssertNotNil(pk, nil);
    STAssertEqualObjects([data mutableCopy], [pk keyData], nil);
}

- (void)testPublicKeyReturnsErrorOnBadLength {
    NSError *error = nil;
    ObjcNaClBoxPublicKey *pk = [ObjcNaClBoxPublicKey keyWithData:STR2DATA("too short") error:&error];
    STAssertNil(pk, nil);
    AssertError(error, 2, ObjcNaClErrorDomain, @"incorrect public-key length");
}

- (void)testPublicKeyErrorIgnoresErrorParam {
    STAssertNil([ObjcNaClBoxPublicKey keyWithData:STR2DATA("too short") error:NULL], nil);
}

- (void)testSecretKey {
    NSData *data = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey keyWithData:data error:NULL];
    STAssertNotNil(sk, nil);
    STAssertEqualObjects([data mutableCopy], [sk keyData], nil);
}

- (void)testSecretKeyReturnsErrorOnBadLength {
    NSError *error = nil;
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey keyWithData:STR2DATA("too short") error:&error];
    STAssertNil(sk, nil);
    AssertError(error, 3, ObjcNaClErrorDomain, @"incorrect secret-key length");
}

- (void)testSecretKeyErrorIgnoresErrorParam {
    STAssertNil([ObjcNaClBoxSecretKey keyWithData:STR2DATA("too short") error:NULL], nil);
}

- (void)testSecretKeyCreatesPublicKey {
    NSData *data = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey keyWithData:data error:NULL];
    ObjcNaClBoxPublicKey *pk = [sk publicKey];
    STAssertNotNil(pk, nil);
    STAssertEqualObjects(HEX2DATA("ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"), [pk keyData], nil);
}

- (void)testGenerateSecretKey {
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey new];
    STAssertNotNil(sk, nil);
    STAssertEqualObjects(HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), [sk keyData], nil);
    STAssertEqualObjects(HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), [[sk publicKey] keyData], nil);
}

@end


@implementation ObjcNaClBoxNonceTest

- (void)testValid {
    NSData *data = HEX2DATA("434343434343434343434343434343434343434343434343");
    ObjcNaClBoxNonce *nonce = [ObjcNaClBoxNonce nonceWithData:data error:NULL];
    STAssertNotNil(nonce, nil);
    STAssertEqualObjects([data mutableCopy], [nonce nonceData], nil);
}

- (void)testNonceReturnsErrorOnBadLength {
    NSError *error = nil;
    ObjcNaClBoxNonce *nonce = [ObjcNaClBoxNonce nonceWithData:STR2DATA("too short") error:&error];
    STAssertNil(nonce, nil);
    AssertError(error, 1, ObjcNaClErrorDomain, @"incorrect nonce length");
}

- (void)testPublicKeyErrorIgnoresErrorParam {
    STAssertNil([ObjcNaClBoxNonce nonceWithData:STR2DATA("too short") error:NULL], nil);
}

@end


static NSData *STR2DATA(const char *x) {
    return [NSData dataWithBytes:x length:strlen(x)];
}

static NSData *HEX2DATA(const char *x) {
    return [NSData dataWithHexCString:x];
}
