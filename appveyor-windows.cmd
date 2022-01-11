vcpkg list

if exist ".\boringssl\CMakeLists.txt" (
    echo cached
) else (
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    git checkout cf8d3ad3cea51cf7184307d54f465da62b7d8408
    cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=OFF -DOPENSSL_NO_ASM=1 .
    msbuild /m ALL_BUILD.vcxproj
    cd ..
)

git submodule init

git submodule update --checkout --force --recursive

set VCPKG_ROOT=c:/tools/vcpkg/

cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DBUILD_SHARED_LIBS=OFF -DVCPKG_TARGET_TRIPLET=x64-windows-static -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=c:/tools/vcpkg/scripts/buildsystems/vcpkg.cmake -DGETOPT_INCLUDE_DIR=c:/tools/vcpkg/installed/x64-windows/include  -DGETOPT_LIB=c:/tools/vcpkg/installed/x64-windows/lib/getopt.lib -DBORINGSSL_DIR=%cd%\boringssl .


msbuild /m ALL_BUILD.vcxproj
