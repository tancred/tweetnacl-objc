CC = clang
CFLAGS = -Wall -fobjc-arc -F/Applications/Xcode.app/Contents/Developer/Library/Frameworks
PROGS = tests

default: $(PROGS)
	DYLD_FRAMEWORK_PATH=/Applications/Xcode.app/Contents/Developer/Library/Frameworks ./tests

tests: tests.o tweetnacl-objc.o tweetnacl.o randombytes_deterministic.o
	$(CC) -o $@ $(CFLAGS) $^ -framework Foundation -framework SenTestingKit

tests.o: \
	tests.m

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
