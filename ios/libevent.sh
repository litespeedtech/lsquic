# libevent_ios
# iOS平台的libevent库编译脚本

````
###########################################################################
# Choose your libevent version and your currently-installed iOS SDK version:
#
VERSION="2.1.8-stable"
USERSDKVERSION="11.4"
MINIOSVERSION="9.0"
VERIFYGPG=false

###########################################################################
#
# Don't change anything under this line!
#
###########################################################################

# No need to change this since xcode build will only compile in the
# necessary bits from the libraries we create
ARCHS="i386 x86_64 armv7 armv7s arm64"

DEVELOPER=`xcode-select -print-path`
#DEVELOPER="/Applications/Xcode.app/Contents/Developer"

# for continuous integration
# https://travis-ci.org/mtigas/iOS-OnionBrowser
if [ "$1" == "--noverify" ]; then
	VERIFYGPG=false
fi
if [ "$2" == "--travis" ]; then
	ARCHS="i386 x86_64"
fi

if [[ ! -z "$TRAVIS" && $TRAVIS ]]; then
	# Travis CI highest available version
	echo "==================== TRAVIS CI ===================="
	SDKVERSION="${USERSDKVERSION}"
else
	SDKVERSION="${USERSDKVERSION}"
fi

cd "`dirname \"$0\"`"
REPOROOT=$(pwd)

# Where we'll end up storing things in the end
OUTPUTDIR="${REPOROOT}/dependencies"
mkdir -p ${OUTPUTDIR}/include
mkdir -p ${OUTPUTDIR}/lib


BUILDDIR="${REPOROOT}/build"

# where we will keep our sources and build from.
SRCDIR="${BUILDDIR}/src"
mkdir -p $SRCDIR
# where we will store intermediary builds
INTERDIR="${BUILDDIR}/built"
mkdir -p $INTERDIR

########################################

cd $SRCDIR

# Exit the script if an error happens
set -e

if [ ! -e "${SRCDIR}/libevent-${VERSION}.tar.gz" ]; then
	echo "Downloading libevent-${VERSION}.tar.gz"
	curl -LO https://github.com/libevent/libevent/releases/download/release-${VERSION}/libevent-${VERSION}.tar.gz
fi
echo "Using libevent-${VERSION}.tar.gz"

# up to you to set up `gpg` and add keys to your keychain
# may have to import from link on http://www.wangafu.net/~nickm/ or http://www.citi.umich.edu/u/provos/
if $VERIFYGPG; then
	if [ ! -e "${SRCDIR}/libevent-${VERSION}.tar.gz.asc" ]; then
		curl -LO https://github.com/libevent/libevent/releases/download/release-${VERSION}/libevent-${VERSION}.tar.gz.asc
	fi
	echo "Using libevent-${VERSION}.tar.gz.asc"
	if out=$(gpg --status-fd 1 --verify "libevent-${VERSION}.tar.gz.asc" "libevent-${VERSION}.tar.gz" 2>/dev/null) &&
	echo "$out" | grep -qs "^\[GNUPG:\] VALIDSIG"; then
		echo "$out" | egrep "GOODSIG|VALIDSIG"
		echo "Verified GPG signature for source..."
	else
		echo "$out" >&2
		echo "COULD NOT VERIFY PACKAGE SIGNATURE..."
		exit 1
	fi
fi

tar zxf libevent-${VERSION}.tar.gz -C $SRCDIR
cd "${SRCDIR}/libevent-${VERSION}"

set +e # don't bail out of bash script if ccache doesn't exist
CCACHE=`which ccache`
if [ $? == "0" ]; then
	echo "Building with ccache: $CCACHE"
	CCACHE="${CCACHE} "
else
	echo "Building without ccache"
	CCACHE=""
fi
set -e # back to regular "bail out on error" mode

export ORIGINALPATH=$PATH

for ARCH in ${ARCHS}
do
	if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ];
	then
		PLATFORM="iPhoneSimulator"
		EXTRA_CONFIG="--host=${ARCH}-apple-darwin"
	else
		PLATFORM="iPhoneOS"
		EXTRA_CONFIG="--host=arm-apple-darwin"
	fi

	mkdir -p "${INTERDIR}/${PLATFORM}${SDKVERSION}-${ARCH}.sdk"

	export PATH="${DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin/:${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer/usr/bin/:${DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin:${DEVELOPER}/usr/bin:${ORIGINALPATH}"
	export CC="${CCACHE}`which gcc` -arch ${ARCH} -miphoneos-version-min=${MINIOSVERSION}"

	./configure --disable-shared --enable-static --disable-debug-mode ${EXTRA_CONFIG} --disable-clock-gettime \
	--prefix="${INTERDIR}/${PLATFORM}${SDKVERSION}-${ARCH}.sdk" \
	LDFLAGS="$LDFLAGS -L${OUTPUTDIR}/lib" \
	CFLAGS="$CFLAGS -Os -I${OUTPUTDIR}/include -isysroot ${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer/SDKs/${PLATFORM}${SDKVERSION}.sdk -fembed-bitcode" \
	CPPFLAGS="$CPPFLAGS -I${OUTPUTDIR}/include -isysroot ${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer/SDKs/${PLATFORM}${SDKVERSION}.sdk -fembed-bitcode"

	# Build the application and install it to the fake SDK intermediary dir
	# we have set up. Make sure to clean up afterward because we will re-use
	# this source tree to cross-compile other targets.
	make -j$(sysctl hw.ncpu | awk '{print $2}')
	make install
	make clean
done

########################################

echo "Build library..."

# These are the libs that comprise libevent. `libevent_openssl` and `libevent_pthreads`
# may not be compiled if those dependencies aren't available.
OUTPUT_LIBS="libevent.a libevent_core.a libevent_extra.a libevent_openssl.a libevent_pthreads.a"
for OUTPUT_LIB in ${OUTPUT_LIBS}; do
	INPUT_LIBS=""
	for ARCH in ${ARCHS}; do
		if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ];
		then
			PLATFORM="iPhoneSimulator"
		else
			PLATFORM="iPhoneOS"
		fi
		INPUT_ARCH_LIB="${INTERDIR}/${PLATFORM}${SDKVERSION}-${ARCH}.sdk/lib/${OUTPUT_LIB}"
		if [ -e $INPUT_ARCH_LIB ]; then
			INPUT_LIBS="${INPUT_LIBS} ${INPUT_ARCH_LIB}"
		fi
	done
	# Combine the three architectures into a universal library.
	if [ -n "$INPUT_LIBS"  ]; then
		lipo -create $INPUT_LIBS \
		-output "${OUTPUTDIR}/lib/${OUTPUT_LIB}"
	else
		echo "$OUTPUT_LIB does not exist, skipping (are the dependencies installed?)"
	fi
done

for ARCH in ${ARCHS}; do
	if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ];
	then
		PLATFORM="iPhoneSimulator"
	else
		PLATFORM="iPhoneOS"
	fi
	cp -R ${INTERDIR}/${PLATFORM}${SDKVERSION}-${ARCH}.sdk/include/* ${OUTPUTDIR}/include/
	if [ $? == "0" ]; then
		# We only need to copy the headers over once. (So break out of forloop
		# once we get first success.)
		break
	fi
done


####################

echo "Building done."
echo "Cleaning up..."
rm -fr ${INTERDIR}
rm -fr "${SRCDIR}/libevent-${VERSION}"
echo "Done."

````
