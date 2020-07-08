.PHONY: all clean
all:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything maphys.c -o maphys -framework IOKit -framework CoreFoundation -lcompression -O2

clean:
	$(RM) maphys
