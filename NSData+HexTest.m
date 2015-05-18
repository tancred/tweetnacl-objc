#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#import "NSData+Hex.h"


@interface DataFromHexTest : XCTestCase
@end


@implementation DataFromHexTest

- (void)testEmpty {
    XCTAssertEqualObjects([NSData dataWithHexCString:""], [NSData data]);
}

- (void)testValid {
    XCTAssertEqualObjects([NSData dataWithHexCString:"0"], [NSData dataWithBytes:"\000" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"1"], [NSData dataWithBytes:"\001" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"a"], [NSData dataWithBytes:"\012" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"A"], [NSData dataWithBytes:"\012" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"f"], [NSData dataWithBytes:"\017" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"F"], [NSData dataWithBytes:"\017" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"10"], [NSData dataWithBytes:"\020" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"7f"], [NSData dataWithBytes:"\177" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"80"], [NSData dataWithBytes:"\200" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"ff"], [NSData dataWithBytes:"\377" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"100"], [NSData dataWithBytes:"\001\000" length:2]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"ffef"], [NSData dataWithBytes:"\377\357" length:2]);
}

- (void)testZeroes {
    XCTAssertEqualObjects([NSData dataWithHexCString:"0"], [NSData dataWithBytes:"\000" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"00"], [NSData dataWithBytes:"\000" length:1]);
    XCTAssertEqualObjects([NSData dataWithHexCString:"000"], [NSData dataWithBytes:"\000\000" length:2]);
}

- (void)testInvalid {
    XCTAssertEqualObjects([NSData dataWithHexCString:"g"], nil);
    XCTAssertEqualObjects([NSData dataWithHexCString:"0g"], nil);
    XCTAssertEqualObjects([NSData dataWithHexCString:"0 "], nil);
    XCTAssertEqualObjects([NSData dataWithHexCString:" 0"], nil);
}

@end
