#import <Foundation/Foundation.h>

@interface NSData (HexAdditions)
+ (NSData *)dataWithHexCString:(const char *)hexstr;
@end
