ARCH = arm64
CC = clang
CFLAGS = -arch $(ARCH) -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -F/System/Library/Frameworks -framework Foundation -O2
LDFLAGS = -dynamiclib -install_name @rpath/bypass.dylib

all: bypass.dylib

bypass.dylib: bypass.o fishhook.o
	$(CC) $(CFLAGS) -Xlinker $(LDFLAGS) -o $@ $^

bypass.o: bypass.m fishhook.h
	$(CC) $(CFLAGS) -c bypass.m

fishhook.o: fishhook.c fishhook.h
	$(CC) $(CFLAGS) -c fishhook.c

clean:
	rm -f *.o *.dylib