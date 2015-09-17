#import <XCTest/XCTest.h>
#import "tweetnacl-objc.h"
#import "tweetnacl.h"
#import "NSData+Hex.h"

#define AssertError(actualError, expectedCode, expectedDomain, expectedDesc) \
do { \
    XCTAssertNotNil((actualError)); \
    if (!(actualError)) break; \
    XCTAssertEqual([(actualError) code], (NSInteger)(expectedCode), @"code"); \
    XCTAssertEqualObjects([(actualError) domain], expectedDomain, @"domain"); \
    XCTAssertEqualObjects([[(actualError) userInfo] objectForKey:NSLocalizedDescriptionKey], (expectedDesc), @"description"); \
} while(0)


static NSData *STR2DATA(const char *x);
static NSData *HEX2DATA(const char *x);


@interface ObjcNaClBoxTest : XCTestCase
@property(strong) ObjcNaClBoxSecretKey *alicesKey;
@property(strong) ObjcNaClBoxSecretKey *bobsKey;
@property(strong) ObjcNaClBoxNonce *nonce;
@property(strong) NSData *aliceMessage;
@property(strong) NSData *aliceCipher;
@end

@interface ObjcNaClBoxKeyTest : XCTestCase
@end

@interface ObjcNaClBoxNonceTest : XCTestCase
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
    XCTAssertEqualObjects(c, aliceCipher);
    XCTAssertNil(error);
}

- (void)testBoxFailsOnInvalidKeyArguments {
    NSError *error = nil;
    ObjcNaClBox *box = [ObjcNaClBox boxWithSecretKey:nil publicKey:nil error:&error];
    XCTAssertNil(box);
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid secret key");

    error = nil;
    box = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:nil error:&error];
    XCTAssertNil(box);
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid public key");
}

- (void)testEncryptFailsOnInvalidMessage {
    ObjcNaClBox *alicesBox = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:[bobsKey publicKey] error:NULL];
    NSError *error = nil;
    XCTAssertNil([alicesBox encryptMessage:nil withNonce:nonce error:&error], @"message");
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid message");
}

- (void)testEncryptFailsOnInvalidNonce {
    ObjcNaClBox *alicesBox = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:[bobsKey publicKey] error:NULL];
    NSError *error = nil;
    XCTAssertNil([alicesBox encryptMessage:aliceMessage withNonce:nil error:&error], @"nonce");
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid nonce");
}

- (void)testDecrypt {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    XCTAssertEqualObjects(m, aliceMessage);
    XCTAssertNil(error);
}

- (void)testDecryptFailsOnInvalidCipher {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    XCTAssertNil([bobsBox decryptCipher:nil withNonce:nonce error:&error], @"cipher");
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid cipher");
}

- (void)testDecryptFailsOnInvalidNonce {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    XCTAssertNil([bobsBox decryptCipher:aliceCipher withNonce:nil error:&error], @"nonce");
    AssertError(error, 0, ObjcNaClErrorDomain, @"invalid nonce");
}

- (void)testBoxOpenFailsWithBadPublicKey {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[bobsKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    XCTAssertNil(m, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

- (void)testBoxOpenFailsWithBadSecretKey {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:alicesKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    XCTAssertNil(m, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

- (void)testBoxOpenFailsWithBadNonce {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    nonce = [ObjcNaClBoxNonce nonceWithData:HEX2DATA("434343434343434343434343434343434343434343434344") error:NULL];
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    XCTAssertNil(m, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

- (void)testBoxOpenFailsWithChangedCipher {
    ObjcNaClBox *bobsBox = [ObjcNaClBox boxWithSecretKey:bobsKey publicKey:[alicesKey publicKey] error:NULL];
    NSError *error = nil;
    aliceCipher  = HEX2DATA("bb9fa648e55b759aeaf62785214fedf4d3d60a6bfc40661a7ec0cc4494");
    NSData *m = [bobsBox decryptCipher:aliceCipher withNonce:nonce error:&error];
    XCTAssertNil(m, @"message");
    AssertError(error, -1, ObjcNaClErrorDomain, @"ciphertext verification failed");
}

@end


@implementation ObjcNaClBoxKeyTest

- (void)testPublicKey {
    NSData *data = HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22");
    ObjcNaClBoxPublicKey *pk = [ObjcNaClBoxPublicKey keyWithData:data error:NULL];
    XCTAssertNotNil(pk);
    XCTAssertEqualObjects([data mutableCopy], [pk keyData]);
}

- (void)testPublicKeyReturnsErrorOnBadLength {
    NSError *error = nil;
    ObjcNaClBoxPublicKey *pk = [ObjcNaClBoxPublicKey keyWithData:STR2DATA("too short") error:&error];
    XCTAssertNil(pk, @"key");
    AssertError(error, 2, ObjcNaClErrorDomain, @"incorrect public-key length");
}

- (void)testPublicKeyErrorIgnoresErrorParam {
    XCTAssertNil([ObjcNaClBoxPublicKey keyWithData:STR2DATA("too short") error:NULL]);
}

- (void)testPublicKeyReturnsNilOnInit {
    XCTAssertNil([[ObjcNaClBoxPublicKey alloc] init]);
}

- (void)testSecretKey {
    NSData *data = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey keyWithData:data error:NULL];
    XCTAssertNotNil(sk);
    XCTAssertEqualObjects([data mutableCopy], [sk keyData]);
}

- (void)testSecretKeyReturnsErrorOnBadLength {
    NSError *error = nil;
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey keyWithData:STR2DATA("too short") error:&error];
    XCTAssertNil(sk, @"key");
    AssertError(error, 3, ObjcNaClErrorDomain, @"incorrect secret-key length");
}

- (void)testSecretKeyErrorIgnoresErrorParam {
    XCTAssertNil([ObjcNaClBoxSecretKey keyWithData:STR2DATA("too short") error:NULL]);
}

- (void)testSecretKeyCreatesPublicKey {
    NSData *data = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey keyWithData:data error:NULL];
    ObjcNaClBoxPublicKey *pk = [sk publicKey];
    XCTAssertNotNil(pk);
    XCTAssertEqualObjects(HEX2DATA("ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"), [pk keyData]);
}

- (void)testGenerateSecretKey {
    ObjcNaClBoxSecretKey *sk = [ObjcNaClBoxSecretKey new];
    XCTAssertNotNil(sk);
    XCTAssertEqualObjects(HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), [sk keyData]);
    XCTAssertEqualObjects(HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), [[sk publicKey] keyData]);
}

@end


@implementation ObjcNaClBoxNonceTest

- (void)testValid {
    NSData *data = HEX2DATA("434343434343434343434343434343434343434343434343");
    ObjcNaClBoxNonce *nonce = [ObjcNaClBoxNonce nonceWithData:data error:NULL];
    XCTAssertNotNil(nonce);
    XCTAssertEqualObjects([data mutableCopy], [nonce nonceData]);
}

- (void)testNonceReturnsErrorOnBadLength {
    NSError *error = nil;
    ObjcNaClBoxNonce *nonce = [ObjcNaClBoxNonce nonceWithData:STR2DATA("too short") error:&error];
    XCTAssertNil(nonce, @"nonce");
    AssertError(error, 1, ObjcNaClErrorDomain, @"incorrect nonce length");
}

- (void)testPublicKeyErrorIgnoresErrorParam {
    XCTAssertNil([ObjcNaClBoxNonce nonceWithData:STR2DATA("too short") error:NULL]);
}

@end


static NSData *STR2DATA(const char *x) {
    return [NSData dataWithBytes:x length:strlen(x)];
}

static NSData *HEX2DATA(const char *x) {
    return [NSData dataWithHexCString:x];
}
