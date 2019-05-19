.PHONY: all
all:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything maphys.c -o maphys -framework IOKit -O2
	codesign -s - --entitlements tfp0.plist maphys

.PHONY: clean
clean:
	$(RM) maphys
