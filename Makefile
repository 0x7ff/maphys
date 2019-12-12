.PHONY: all clean
all:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything maphys.c -o maphys -framework IOKit -framework CoreFoundation -O2

clean:
	$(RM) maphys
