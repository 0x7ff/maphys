.PHONY: all clean
all:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything maphys.c -o maphys -framework IOKit -O2

clean:
	$(RM) maphys
