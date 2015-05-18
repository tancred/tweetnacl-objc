CC = clang
PLATFORM_SDK_PATH=$(shell xcrun --show-sdk-platform-path)
PLATFORM_FRAMEWORKS_PATH=$(PLATFORM_SDK_PATH)/Developer/Library/Frameworks
CFLAGS = -Wall -fobjc-arc -F$(PLATFORM_FRAMEWORKS_PATH)
PROGS = tests


default: $(PROGS)
	DYLD_FRAMEWORK_PATH=$(PLATFORM_FRAMEWORKS_PATH) ./tests 2>&1 | xcpretty -cs

tests: \
	tests.o \
	tweetnacl-objc.o \
	tweetnacl.o \
	randombytes_deterministic.o \
	NSData+Hex.o \
	NSData+HexTest.o \
	ObjcNaClBoxTest.o
	$(CC) -o $@ $(CFLAGS) $^ -framework Foundation -framework XCTest

tests.o: \
	tests.m

NSData+HexTest.o: NSData+HexTest.m NSData+Hex.h
ObjcNaClBoxTest.o: ObjcNaClBoxTest.m tweetnacl-objc.h

tweetnacl-objc.o: \
	tweetnacl-objc.m \
	tweetnacl-objc.h \
	tweetnacl.h

tweetnacl.o: \
	tweetnacl.c \
	tweetnacl.h

randombytes_deterministic.o: \
	randombytes_deterministic.c \
	randombytes_deterministic.h

%.o: %.c
	$(CC) -c $(CFLAGS) $<

%.o: %.m
	$(CC) -c $(CFLAGS) $<

clean:
	rm -f *.o
	rm -f $(PROGS)
