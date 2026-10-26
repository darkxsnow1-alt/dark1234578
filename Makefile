ARCHS = arm64
TARGET = iphone:clang:latest:14.0

all: Bypass.dylib

Bypass.dylib: Bypass.mm
    xcrun -sdk iphoneos clang -arch arm64 -dynamiclib -o Bypass.dylib Bypass.mm -framework Foundation -framework UIKit

clean:
    rm -f Bypass.dylib