# Builds a ZLib framework for the iPhone and the iPhone Simulator.
# Creates a set of universal libraries that can be used on an iPhone and in the
# iPhone simulator. Then creates a pseudo-framework to make using libz in Xcode
# less painful.
#
# To configure the script, define:
#    IPHONE_SDKVERSION: iPhone SDK version (e.g. 8.1)
#
# Then go get the source tar.bz of the libz you want to build, shove it in the
# same directory as this script, and run "./libz.sh". Grab a cuppa. And voila.
#===============================================================================

: ${LIB_VERSION:=1.2.8}

# Current iPhone SDK
: ${IPHONE_SDKVERSION:=`xcodebuild -showsdks | grep iphoneos | egrep "[[:digit:]]+\.[[:digit:]]+" -o | tail -1`}
# Specific iPhone SDK
# : ${IPHONE_SDKVERSION:=8.1}

: ${XCODE_ROOT:=`xcode-select -print-path`}

: ${TARBALLDIR:=`pwd`}
: ${SRCDIR:=`pwd`/src}
: ${IOSBUILDDIR:=`pwd`/ios/build}
: ${OSXBUILDDIR:=`pwd`/osx/build}
: ${PREFIXDIR:=`pwd`/ios/prefix}
: ${IOSFRAMEWORKDIR:=`pwd`/ios/framework}
: ${OSXFRAMEWORKDIR:=`pwd`/osx/framework}

LIB_TARBALL=$TARBALLDIR/zlib-$LIB_VERSION.tar.gz
LIB_SRC=$SRCDIR/zlib-${LIB_VERSION}

#===============================================================================
ARM_DEV_CMD="xcrun --sdk iphoneos"
SIM_DEV_CMD="xcrun --sdk iphonesimulator"

#===============================================================================
# Functions
#===============================================================================

abort()
{
    echo
    echo "Aborted: $@"
    exit 1
}

doneSection()
{
    echo
    echo "================================================================="
    echo "Done"
    echo
}

#===============================================================================

cleanEverythingReadyToStart()
{
    echo Cleaning everything before we start to build...

    rm -rf iphone-build iphonesim-build
    rm -rf $IOSBUILDDIR
    rm -rf $PREFIXDIR
    rm -rf $IOSFRAMEWORKDIR/$FRAMEWORK_NAME.framework

    doneSection
}

#===============================================================================

downloadZLib()
{
    if [ ! -s $LIB_TARBALL ]; then
        echo "Downloading zlib ${LIB_VERSION}"
        curl -L -o $LIB_TARBALL http://sourceforge.net/projects/libpng/files/zlib/${LIB_VERSION}/zlib-${LIB_VERSION}.tar.gz
    fi

    doneSection
}

#===============================================================================

unpackZLib()
{
    [ -f "$LIB_TARBALL" ] || abort "Source tarball missing."

    echo Unpacking zlib into $SRCDIR...

    [ -d $SRCDIR ]    || mkdir -p $SRCDIR
    [ -d $LIB_SRC ] || ( cd $SRCDIR; tar xfj $LIB_TARBALL )
    [ -d $LIB_SRC ] && echo "    ...unpacked as $LIB_SRC"

    doneSection
}

#===============================================================================

buildZLibForIPhoneOS()
{
    export CC=$XCODE_ROOT/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
    export CC_BASENAME=clang

    export CXX=$XCODE_ROOT/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++
    export CXX_BASENAME=clang++

    cd $LIB_SRC

    echo Building ZLib for iPhoneSimulator
    export CFLAGS="-O3 -arch i386 -arch x86_64 -isysroot $XCODE_ROOT/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator${IPHONE_SDKVERSION}.sdk -mios-simulator-version-min=9.0 -fembed-bitcode -Wno-error-implicit-function-declaration"
    ./configure --prefix=$PREFIXDIR/iphonesim-build
    make
    make install
    doneSection

    echo Building ZLib for iPhone
    export CFLAGS="-O3 -arch armv7 -arch armv7s -arch arm64 -isysroot $XCODE_ROOT/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS${IPHONE_SDKVERSION}.sdk -mios-version-min=9.0 -fembed-bitcode"
    ./configure --prefix=$PREFIXDIR/iphone-build
    make
    make install
    doneSection
}

#===============================================================================

scrunchAllLibsTogetherInOneLibPerPlatform()
{
    cd $PREFIXDIR

    # iOS Device
    mkdir -p $IOSBUILDDIR/armv7
    mkdir -p $IOSBUILDDIR/armv7s
    mkdir -p $IOSBUILDDIR/arm64

    # iOS Simulator
    mkdir -p $IOSBUILDDIR/i386
    mkdir -p $IOSBUILDDIR/x86_64

    echo Splitting all existing fat binaries...

    $ARM_DEV_CMD lipo "iphone-build/lib/libz.a" -thin armv7 -o $IOSBUILDDIR/armv7/libz.a
    $ARM_DEV_CMD lipo "iphone-build/lib/libz.a" -thin armv7s -o $IOSBUILDDIR/armv7s/libz.a
    $ARM_DEV_CMD lipo "iphone-build/lib/libz.a" -thin arm64 -o $IOSBUILDDIR/arm64/libz.a

    $SIM_DEV_CMD lipo "iphonesim-build/lib/libz.a" -thin i386 -o $IOSBUILDDIR/i386/libz.a
    $SIM_DEV_CMD lipo "iphonesim-build/lib/libz.a" -thin x86_64 -o $IOSBUILDDIR/x86_64/libz.a

    lipo -create $IOSBUILDDIR/armv7/libz.a $IOSBUILDDIR/armv7s/libz.a $IOSBUILDDIR/arm64/libz.a $IOSBUILDDIR/i386/libz.a $IOSBUILDDIR/x86_64/libz.a -output ./libz_all.a
}

#===============================================================================
buildFramework()
{
    : ${1:?}
    FRAMEWORKDIR=$1
    BUILDDIR=$2

    VERSION_TYPE=Alpha
    FRAMEWORK_NAME=zlib
    FRAMEWORK_VERSION=A

    FRAMEWORK_CURRENT_VERSION=$LIB_VERSION
    FRAMEWORK_COMPATIBILITY_VERSION=$LIB_VERSION

    FRAMEWORK_BUNDLE=$FRAMEWORKDIR/$FRAMEWORK_NAME.framework
    echo "Framework: Building $FRAMEWORK_BUNDLE from $BUILDDIR..."

    rm -rf $FRAMEWORK_BUNDLE

    echo "Framework: Setting up directories..."
    mkdir -p $FRAMEWORK_BUNDLE
    mkdir -p $FRAMEWORK_BUNDLE/Versions
    mkdir -p $FRAMEWORK_BUNDLE/Versions/$FRAMEWORK_VERSION
    mkdir -p $FRAMEWORK_BUNDLE/Versions/$FRAMEWORK_VERSION/Resources
    mkdir -p $FRAMEWORK_BUNDLE/Versions/$FRAMEWORK_VERSION/Headers
    mkdir -p $FRAMEWORK_BUNDLE/Versions/$FRAMEWORK_VERSION/Documentation

   # echo "Framework: Creating symlinks..."
   # ln -s $FRAMEWORK_VERSION               $FRAMEWORK_BUNDLE/Versions/Current
   # ln -s Versions/Current/Headers         $FRAMEWORK_BUNDLE/Headers
   # ln -s Versions/Current/Resources       $FRAMEWORK_BUNDLE/Resources
   # ln -s Versions/Current/Documentation   $FRAMEWORK_BUNDLE/Documentation
   # ln -s Versions/Current/$FRAMEWORK_NAME $FRAMEWORK_BUNDLE/$FRAMEWORK_NAME

    FRAMEWORK_INSTALL_NAME=$FRAMEWORK_BUNDLE/Versions/$FRAMEWORK_VERSION/$FRAMEWORK_NAME

    echo "Lipoing library into $FRAMEWORK_INSTALL_NAME..."
    $ARM_DEV_CMD lipo -create $BUILDDIR/*/libz.a -o "$FRAMEWORK_INSTALL_NAME" || abort "Lipo $1 failed"

    echo "Framework: Copying includes..."
    cp -r $PREFIXDIR/iphone-build/include/*  $FRAMEWORK_BUNDLE/Headers/

    echo "Framework: Creating plist..."
    cat > $FRAMEWORK_BUNDLE/Resources/Info.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleDevelopmentRegion</key>
<string>English</string>
<key>CFBundleExecutable</key>
<string>${FRAMEWORK_NAME}</string>
<key>CFBundleIdentifier</key>
<string>org.zlib</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>FMWK</string>
<key>CFBundleSignature</key>
<string>????</string>
<key>CFBundleVersion</key>
<string>${FRAMEWORK_CURRENT_VERSION}</string>
</dict>
</plist>
EOF

    doneSection
}

#===============================================================================
# Execution starts here
#===============================================================================

mkdir -p $IOSBUILDDIR
mkdir -p $PREFIXDIR
# cleanEverythingReadyToStart #may want to comment if repeatedly running during dev

echo "LIB_VERSION:       $LIB_VERSION"
echo "LIB_SRC:           $LIB_SRC"
echo "IOSBUILDDIR:       $IOSBUILDDIR"
echo "PREFIXDIR:         $PREFIXDIR"
echo "IOSFRAMEWORKDIR:   $IOSFRAMEWORKDIR"
echo "IPHONE_SDKVERSION: $IPHONE_SDKVERSION"
echo "XCODE_ROOT:        $XCODE_ROOT"
echo

downloadZLib
unpackZLib
buildZLibForIPhoneOS
scrunchAllLibsTogetherInOneLibPerPlatform
# buildFramework $IOSFRAMEWORKDIR $IOSBUILDDIR

echo "Completed successfully"

#===============================================================================
