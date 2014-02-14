#import "NSData+Hex.h"

static int hexchar2value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

@implementation NSData (HexAdditions)

+ (NSData *)dataWithHexCString:(const char *)x {
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

@end
