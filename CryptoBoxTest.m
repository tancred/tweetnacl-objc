#import <SenTestingKit/SenTestingKit.h>
#import "tweetnacl-objc.h"
#import "tweetnacl.h"


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
static int hexchar2value(unsigned char c);


@interface CryptoBoxTest : SenTestCase
@property(strong) CryptoBoxSecretKey *alicesKey;
@property(strong) CryptoBoxSecretKey *bobsKey;
@property(strong) CryptoBoxNonce *nonce;
@property(strong) NSData *aliceMessage;
@property(strong) NSData *aliceCipher;
@end

@interface CryptoBoxKeyTest : SenTestCase
@end

@interface CryptoBoxNonceTest : SenTestCase
@end


@implementation CryptoBoxTest
@synthesize alicesKey, bobsKey, nonce, aliceMessage, aliceCipher;

- (void)setUp {
    alicesKey    = [CryptoBoxSecretKey keyWithData:HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303") error:NULL];
    bobsKey      = [CryptoBoxSecretKey keyWithData:HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404") error:NULL];
    nonce        = [CryptoBoxNonce nonceWithData:HEX2DATA("434343434343434343434343434343434343434343434343") error:NULL];
    aliceMessage = STR2DATA("Hello, World!");
    aliceCipher  = HEX2DATA("bb9fa648e55b759aeaf62785214fedf4d3d60a6bfc40661a7ec0cc4493");
}

- (void)testEncrypt {
    CryptoBox *alicesBox = [CryptoBox boxWithSecretKey:alicesKey publicKey:[bobsKey publicKey]];
    NSError *error = nil;
    NSData *c = [alicesBox encryptMessage:aliceMessage withNonce:nonce error:&error];
    STAssertEqualObjects(c, aliceCipher, @"cipher");
    STAssertEqualObjects(error, nil, nil);
}

- (void)testEncryptRaisesOnInvalidKeyArguments {
    STAssertThrowsSpecificNamed([CryptoBox boxWithSecretKey:nil publicKey:nil], NSException, NSInvalidArgumentException, @"secret key");
    STAssertThrowsSpecificNamed([CryptoBox boxWithSecretKey:alicesKey publicKey:nil], NSException, NSInvalidArgumentException, @"public key");
}

- (void)testEncryptRaisesOnInvalidEncryptArguments {
    CryptoBox *alicesBox = [CryptoBox boxWithSecretKey:alicesKey publicKey:[bobsKey publicKey]];
    STAssertThrowsSpecificNamed([alicesBox encryptMessage:nil withNonce:nonce error:NULL], NSException, NSInvalidArgumentException, @"message");
    STAssertThrowsSpecificNamed([alicesBox encryptMessage:aliceMessage withNonce:nil error:NULL], NSException, NSInvalidArgumentException, @"nonce");
}

@end


@implementation CryptoBoxKeyTest

- (void)testPublicKey {
    NSData *data = HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22");
    CryptoBoxPublicKey *pk = [CryptoBoxPublicKey keyWithData:data error:NULL];
    STAssertNotNil(pk, nil);
    STAssertEqualObjects([data mutableCopy], [pk keyData], nil);
}

- (void)testPublicKeyReturnsErrorOnBadLength {
    NSError *error = nil;
    CryptoBoxPublicKey *pk = [CryptoBoxPublicKey keyWithData:STR2DATA("too short") error:&error];
    STAssertNil(pk, nil);
    AssertError(error, 2, ObjcNaClErrorDomain, @"incorrect public-key length");
}

- (void)testPublicKeyErrorIgnoresErrorParam {
    STAssertNil([CryptoBoxPublicKey keyWithData:STR2DATA("too short") error:NULL], nil);
}

- (void)testSecretKey {
    NSData *data = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    CryptoBoxSecretKey *sk = [CryptoBoxSecretKey keyWithData:data error:NULL];
    STAssertNotNil(sk, nil);
    STAssertEqualObjects([data mutableCopy], [sk keyData], nil);
}

- (void)testSecretKeyReturnsErrorOnBadLength {
    NSError *error = nil;
    CryptoBoxSecretKey *sk = [CryptoBoxSecretKey keyWithData:STR2DATA("too short") error:&error];
    STAssertNil(sk, nil);
    AssertError(error, 3, ObjcNaClErrorDomain, @"incorrect secret-key length");
}

- (void)testSecretKeyErrorIgnoresErrorParam {
    STAssertNil([CryptoBoxSecretKey keyWithData:STR2DATA("too short") error:NULL], nil);
}

- (void)testSecretKeyCreatesPublicKey {
    NSData *data = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    CryptoBoxSecretKey *sk = [CryptoBoxSecretKey keyWithData:data error:NULL];
    CryptoBoxPublicKey *pk = [sk publicKey];
    STAssertNotNil(pk, nil);
    STAssertEqualObjects(HEX2DATA("ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"), [pk keyData], nil);
}

- (void)testGenerateSecretKey {
    CryptoBoxSecretKey *sk = [CryptoBoxSecretKey new];
    STAssertNotNil(sk, nil);
    STAssertEqualObjects(HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), [sk keyData], nil);
    STAssertEqualObjects(HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), [[sk publicKey] keyData], nil);
}

@end


@implementation CryptoBoxNonceTest

- (void)testValid {
    NSData *data = HEX2DATA("434343434343434343434343434343434343434343434343");
    CryptoBoxNonce *nonce = [CryptoBoxNonce nonceWithData:data error:NULL];
    STAssertNotNil(nonce, nil);
    STAssertEqualObjects([data mutableCopy], [nonce nonceData], nil);
}

- (void)testNonceReturnsErrorOnBadLength {
    NSError *error = nil;
    CryptoBoxNonce *nonce = [CryptoBoxNonce nonceWithData:STR2DATA("too short") error:&error];
    STAssertNil(nonce, nil);
    AssertError(error, 1, ObjcNaClErrorDomain, @"incorrect nonce length");
}

- (void)testPublicKeyErrorIgnoresErrorParam {
    STAssertNil([CryptoBoxNonce nonceWithData:STR2DATA("too short") error:NULL], nil);
}

@end


static NSData *STR2DATA(const char *x) {
    return [NSData dataWithBytes:x length:strlen(x)];
}

static NSData *HEX2DATA(const char *x) {
    int len = strlen(x);
    int odd = (len % 2 != 0) ? 1 : 0;
    int rlen = odd + len/2;

    char *b = (char *)malloc(rlen);
    if (b == NULL) return nil;
    NSData *d = [NSData dataWithBytesNoCopy:b length:rlen freeWhenDone:YES];

    for (int i=0; i<len; i++) {
        int v = hexchar2value(x[i]);
        if (v == -1) return nil;

        char c = (char)(unsigned char)(v & 0xff);
        if (odd) {
            b[0] = c;
            odd = 0;
            continue;
        }

        i++;
        v = hexchar2value(x[i]);
        if (v == -1) return nil;
        c *= 16;
        c += (char)(unsigned char)(v & 0xff);
        b[i/2] = c;
    }

    return d;
}

static int hexchar2value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}
