vcpkg list

if exist ".\boringssl\CMakeLists.txt" (
    echo cached
) else (
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    git checkout a2278d4d2cabe73f6663e3299ea7808edfa306b9
    cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=ON -DOPENSSL_NO_ASM=1 .
    msbuild /m ALL_BUILD.vcxproj
    cd ..
)

git submodule init

git submodule update --checkout --force --recursive

set VCPKG_ROOT=c:/tools/vcpkg/

cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DLSQUIC_SHARED_LIB=ON -DBUILD_SHARED_LIBS=ON -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=c:/tools/vcpkg/scripts/buildsystems/vcpkg.cmake -DBORINGSSL_DIR=%cd%\boringssl -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON .

msbuild /m src/liblsquic/lsquic.vcxproj
msbuild /m build-tests.vcxproj

msbuild /m RUN_TESTS.vcxproj



