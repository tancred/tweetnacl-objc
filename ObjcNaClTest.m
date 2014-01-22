#import <SenTestingKit/SenTestingKit.h>
#import "tweetnacl-objc.h"
#import "tweetnacl.h"

//static NSData *STR2DATA(const char *x);
static NSData *HEX2DATA(const char *x);
static int hexchar2value(unsigned char c);


@interface ObjcNaClTest : SenTestCase
@end

@interface TweetNaClVerificationTest : SenTestCase
@end

@interface TestHelpersTest : SenTestCase
@end


@implementation ObjcNaClTest

- (void)testKeypair {
    NSError *error = nil;
    NSData *sk = nil;
    NSData *pk = ObjcNaClBoxKeypair(&sk, &error);
    STAssertEqualObjects(pk, HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), @"public key");
    STAssertEqualObjects(sk, HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), @"secret key");
    STAssertEqualObjects(error, nil, nil);
}

- (void)testBox {
    NSData *pk = HEX2DATA("4242424242424242424242424242424242424242424242424242424242424242");
    NSData *sk = HEX2DATA("4141414141414141414141414141414141414141414141414141414141414141");
    NSData *n  = HEX2DATA("434343434343434343434343434343434343434343434343");
    NSData *m = [NSData dataWithBytes:"Hello, World!" length:13];

    NSError *error = nil;
    NSData *c = ObjcNaClBox(m, n, pk, sk, &error);

    STAssertEqualObjects(c, HEX2DATA("14290a0c610ce0e237f6abca3089992730027a27cc9097b01333fd5713"), @"cipher");
    STAssertEqualObjects(error, nil, nil);
}

@end


@implementation TweetNaClVerificationTest

- (void)testKeypair {
    NSMutableData *pk = [NSMutableData dataWithLength:crypto_box_PUBLICKEYBYTES];
    NSMutableData *sk = [NSMutableData dataWithLength:crypto_box_SECRETKEYBYTES];
    crypto_box_keypair([pk mutableBytes], [sk mutableBytes]);
    STAssertEqualObjects(pk, HEX2DATA("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"), @"public key");
    STAssertEqualObjects(sk, HEX2DATA("0303030303030303030303030303030303030303030303030303030303030303"), @"secret key");
}

- (void)testBox {
    NSData *pk = HEX2DATA("4242424242424242424242424242424242424242424242424242424242424242");
    NSData *sk = HEX2DATA("4141414141414141414141414141414141414141414141414141414141414141");
    NSData *n  = HEX2DATA("434343434343434343434343434343434343434343434343");
    NSMutableData *m = [NSMutableData dataWithLength:crypto_box_ZEROBYTES];
    [m appendBytes:"Hello, World!" length:13];

    NSMutableData *c = [NSMutableData dataWithLength:[m length]];

    int r = crypto_box([c mutableBytes], [m bytes], [m length], [n bytes], [pk bytes], [sk bytes]);
    STAssertEquals(0, r, @"result");
    STAssertEqualObjects(c, HEX2DATA("0000000000000000000000000000000014290a0c610ce0e237f6abca3089992730027a27cc9097b01333fd5713"), @"cipher");
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
