#import <Foundation/Foundation.h>
#import <SenTestingKit/SenTestingKit.h>
#import "NSData+Hex.h"


@interface DataFromHexTest : SenTestCase
@end


@implementation DataFromHexTest

- (void)testEmpty {
    STAssertEqualObjects([NSData dataWithHexCString:""], [NSData data], nil);
}

- (void)testValid {
    STAssertEqualObjects([NSData dataWithHexCString:"0"], [NSData dataWithBytes:"\000" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"1"], [NSData dataWithBytes:"\001" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"a"], [NSData dataWithBytes:"\012" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"A"], [NSData dataWithBytes:"\012" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"f"], [NSData dataWithBytes:"\017" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"F"], [NSData dataWithBytes:"\017" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"10"], [NSData dataWithBytes:"\020" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"7f"], [NSData dataWithBytes:"\177" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"80"], [NSData dataWithBytes:"\200" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"ff"], [NSData dataWithBytes:"\377" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"100"], [NSData dataWithBytes:"\001\000" length:2], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"ffef"], [NSData dataWithBytes:"\377\357" length:2], nil);
}

- (void)testZeroes {
    STAssertEqualObjects([NSData dataWithHexCString:"0"], [NSData dataWithBytes:"\000" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"00"], [NSData dataWithBytes:"\000" length:1], nil);
    STAssertEqualObjects([NSData dataWithHexCString:"000"], [NSData dataWithBytes:"\000\000" length:2], nil);
}

- (void)testInvalid {
    STAssertEqualObjects([NSData dataWithHexCString:"g"], nil, nil);
    STAssertEqualObjects([NSData dataWithHexCString:"0g"], nil, nil);
    STAssertEqualObjects([NSData dataWithHexCString:"0 "], nil, nil);
    STAssertEqualObjects([NSData dataWithHexCString:" 0"], nil, nil);
}

@end
