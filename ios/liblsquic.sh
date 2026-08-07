# liblsquic_ios
# iOS平台的liblsquic库编译脚本

````
###########################################################################
#
# Don't change anything under this line!
#
###########################################################################

# No need to change this since xcode build will only compile in the
# necessary bits from the libraries we create
ARCHS="armv7 armv7s arm64 i386 x86_64"

DEVELOPER=`xcode-select -print-path`
#DEVELOPER="/Applications/Xcode.app/Contents/Developer"


cd "`dirname \"$0\"`"
REPOROOT=$(pwd)

# Where we'll end up storing things in the end
OUTPUTDIR="${REPOROOT}/output"
mkdir -p ${OUTPUTDIR}/include
mkdir -p ${OUTPUTDIR}/lib

cp ios/CMakeLists_iOS.txt CMakeLists.txt

# Exit the script if an error happens
set -e

set +e # don't bail out of bash script if ccache doesn't exist

export ORIGINALPATH=$PATH

for ARCH in ${ARCHS}
do
	if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ];
	then
		PLATFORM="iphonesimulator"
	else
		PLATFORM="iphoneos"
     	CFLAGS=" -fembed-bitcode"
        CPPFLAGS=" -fembed-bitcode"
	fi

	export PATH="${DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin/:${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer/usr/bin/:${DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin:${DEVELOPER}/usr/bin:${ORIGINALPATH}"

  mkdir -p ${OUTPUTDIR}/lib/${ARCH}

  BORINGSSL_INCLUDE="{your boringssl include path}"
  BORINGSSL_LIB="{your boringssl lib path}"
  
  cmake -DBORINGSSL_INCLUDE="${BORINGSSL_INCLUDE}" \
        -DBORINGSSL_LIB="${BORINGSSL_LIB}" \
        -DCMAKE_C_FLAGS:STRING="${CFLAGS}" \
        -DCMAKE_OSX_SYSROOT="${PLATFORM}" \
        -DCMAKE_OSX_ARCHITECTURES="${ARCH}"
	# Build the application and install it to the fake SDK intermediary dir
	# we have set up. Make sure to clean up afterward because we will re-use
	# this source tree to cross-compile other targets.
	echo "making ${ARCH} ..."
	make -j4
	
	cp src/liblsquic/liblsquic.a ${OUTPUTDIR}/lib/${ARCH}/
	
	echo "make clean"
	make clean
done

########################################

echo "Build library..."

OUTPUT_LIBS="liblsquic.a"
for OUTPUT_LIB in ${OUTPUT_LIBS}; do
		lipo -create ${OUTPUTDIR}/lib/i386/${OUTPUT_LIB} \
		             ${OUTPUTDIR}/lib/x86_64/${OUTPUT_LIB} \
		             ${OUTPUTDIR}/lib/armv7/${OUTPUT_LIB} \
		             ${OUTPUTDIR}/lib/armv7s/${OUTPUT_LIB} \
		             ${OUTPUTDIR}/lib/arm64/${OUTPUT_LIB} \
		-output "${OUTPUTDIR}/lib/${OUTPUT_LIB}"
done


####################

echo "Building done."

````
