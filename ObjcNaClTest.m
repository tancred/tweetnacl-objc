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


//static NSData *STR2DATA(const char *x);
static NSData *HEX2DATA(const char *x);
static int hexchar2value(unsigned char c);


@interface ObjcNaClTest : SenTestCase
@property(strong) NSData *pk;
@property(strong) NSData *sk;
@property(strong) NSData *n;
@property(strong) NSData *m;
@end

@interface TweetNaClVerificationTest : SenTestCase
@property(strong) NSData *alicepk;
@property(strong) NSData *alicesk;
@property(strong) NSData *bobpk;
@property(strong) NSData *bobsk;
@property(strong) NSData *n;
@end

@interface TestHelpersTest : SenTestCase
@end


@implementation ObjcNaClTest
@synthesize pk,sk,n,m;

- (void)setUp {
    pk = HEX2DATA("4242424242424242424242424242424242424242424242424242424242424242");
    sk = HEX2DATA("4141414141414141414141414141414141414141414141414141414141414141");
    n  = HEX2DATA("434343434343434343434343434343434343434343434343");
    m = [NSData dataWithBytes:"Hello, World!" length:13];
}

- (void)testKeypair {
    NSError *error = nil;
    NSData *lsk = nil;
    NSData *lpk = ObjcNaClBoxKeypair(&lsk, &error);
    STAssertEqualObjects(lpk, HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), @"public key");
    STAssertEqualObjects(lsk, HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), @"secret key");
    STAssertEqualObjects(error, nil, nil);
}

- (void)testBox {
    NSError *error = nil;
    NSData *c = ObjcNaClBox(m, n, pk, sk, &error);
    STAssertEqualObjects(c, HEX2DATA("14290a0c610ce0e237f6abca3089992730027a27cc9097b01333fd5713"), @"cipher");
    STAssertEqualObjects(error, nil, nil);
}

- (void)testBoxRequiresCorrectNonceLength {
    NSError *error = nil;
    NSData *c = ObjcNaClBox(m, [NSMutableData dataWithLength:23], pk, sk, &error);
    STAssertNil(c, nil, @"cipher");
    AssertError(error, 1, ObjcNaClErrorDomain, @"incorrect nonce length");
}

- (void)testBoxRequiresCorrectPublicKeyLength {
    NSError *error = nil;
    NSData *c = ObjcNaClBox(m, n, [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES + 1], sk, &error);
    STAssertNil(c, nil, @"cipher");
    AssertError(error, 2, ObjcNaClErrorDomain, @"incorrect public-key length");
}

- (void)testBoxRequiresCorrectSecretKeyLength {
    NSError *error = nil;
    NSData *c = ObjcNaClBox(m, n, pk, [NSMutableData dataWithLength:crypto_box_SECRETKEYBYTES - 1], &error);
    STAssertNil(c, nil, @"cipher");
    AssertError(error, 3, ObjcNaClErrorDomain, @"incorrect secret-key length");
}

@end


@implementation TweetNaClVerificationTest
@synthesize alicepk, alicesk, bobpk, bobsk, n;

- (void)setUp {
    alicepk = HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22");
    alicesk = HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303");
    bobpk   = HEX2DATA("ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b");
    bobsk   = HEX2DATA("0404040404040404040404040404040404040404040404040404040404040404");
    n       = HEX2DATA("434343434343434343434343434343434343434343434343");
}

- (void)testKeypair {
    NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
    NSMutableData *sk = [NSMutableData dataWithLength:crypto_box_SECRETKEYBYTES];
    crypto_box_keypair([pk mutableBytes], [sk mutableBytes]);
    STAssertEqualObjects(pk, HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), @"public key");
    STAssertEqualObjects(sk, HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), @"secret key");
}

- (void)testBox {
    NSMutableData *m = [NSMutableData dataWithLength:crypto_box_ZEROBYTES];
    [m appendBytes:"Hello, World!" length:13];
    NSMutableData *c = [NSMutableData dataWithLength:[m length]];

    int r = crypto_box([c mutableBytes], [m bytes], [m length], [n bytes], [bobpk bytes], [alicesk bytes]);

    STAssertEquals(0, r, @"result");
    STAssertEqualObjects(c, HEX2DATA("00000000000000000000000000000000bb9fa648e55b759aeaf62785214fedf4d3d60a6bfc40661a7ec0cc4493"), @"cipher");
}

- (void)testBoxOpen {
    NSData *c = HEX2DATA("00000000000000000000000000000000bb9fa648e55b759aeaf62785214fedf4d3d60a6bfc40661a7ec0cc4493");
    NSMutableData *m = [NSMutableData dataWithLength:[c length]];

    int r = crypto_box_open([m mutableBytes], [c bytes], [c length], [n bytes], [alicepk bytes], [bobsk bytes]);

    STAssertEquals(0, r, @"result");
    STAssertEqualObjects(m, HEX2DATA("000000000000000000000000000000000000000000000000000000000000000048656c6c6f2c20576f726c6421"), @"message");
}

@end


@implementation TestHelpersTest

- (void)testHex2Data {
    STAssertEqualObjects(HEX2DATA(""), [NSData data], nil);

    STAssertEqualObjects(HEX2DATA("0"), [NSData dataWithBytes:"\000" length:1], nil);
    STAssertEqualObjects(HEX2DATA("1"), [NSData dataWithBytes:"\001" length:1], nil);
    STAssertEqualObjects(HEX2DATA("a"), [NSData dataWithBytes:"\012" length:1], nil);
    STAssertEqualObjects(HEX2DATA("A"), [NSData dataWithBytes:"\012" length:1], nil);
    STAssertEqualObjects(HEX2DATA("f"), [NSData dataWithBytes:"\017" length:1], nil);
    STAssertEqualObjects(HEX2DATA("F"), [NSData dataWithBytes:"\017" length:1], nil);
    STAssertEqualObjects(HEX2DATA("10"), [NSData dataWithBytes:"\020" length:1], nil);
    STAssertEqualObjects(HEX2DATA("7f"), [NSData dataWithBytes:"\177" length:1], nil);
    STAssertEqualObjects(HEX2DATA("80"), [NSData dataWithBytes:"\200" length:1], nil);
    STAssertEqualObjects(HEX2DATA("ff"), [NSData dataWithBytes:"\377" length:1], nil);
    STAssertEqualObjects(HEX2DATA("100"), [NSData dataWithBytes:"\001\000" length:2], nil);
    STAssertEqualObjects(HEX2DATA("ffef"), [NSData dataWithBytes:"\377\357" length:2], nil);

    STAssertEqualObjects(HEX2DATA("0"), [NSData dataWithBytes:"\000" length:1], nil);
    STAssertEqualObjects(HEX2DATA("00"), [NSData dataWithBytes:"\000" length:1], nil);
    STAssertEqualObjects(HEX2DATA("000"), [NSData dataWithBytes:"\000\000" length:2], nil);

    STAssertEqualObjects(HEX2DATA("g"), nil, nil);
    STAssertEqualObjects(HEX2DATA("0g"), nil, nil);
    STAssertEqualObjects(HEX2DATA("0 "), nil, nil);
    STAssertEqualObjects(HEX2DATA(" 0"), nil, nil);
}

@end


//static NSData *STR2DATA(const char *x) {
//    return [NSData dataWithBytes:x length:strlen(x)];
//}

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
