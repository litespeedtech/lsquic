setlocal EnableDelayedExpansion
for /f "usebackq delims=#" %%a in (`"%programfiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -latest -property installationPath`) do call "%%~a\VC\Auxiliary\Build\vcvars64.bat"

set VCPKG_ROOT=c:/tools/vcpkg/

pushd c:\tools\vcpkg\
dir /a /s /b *pcre*.h
popd

vcpkg list

for /f %%t in (boringssl-target.txt) do set BORINGSSL_TARGET=%%t

if exist ".\boringssl\include\openssl\ssl.h" (
    echo boringssl cached
) else (
    git clone https://boringssl.googlesource.com/boringssl
    cd boringssl
    git checkout %BORINGSSL_TARGET%
    rd /s /q .git
    cmake -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=ON -DOPENSSL_NO_ASM=1 .
    msbuild /m crypto\crypto.vcxproj
    if errorlevel 1 exit !errorlevel!
    msbuild /m ssl\ssl.vcxproj
    if errorlevel 1 exit !errorlevel!
    msbuild /m decrepit\decrepit.vcxproj
    if errorlevel 1 exit !errorlevel!
    cd ..
)

git submodule init

set retry_submodule_update=0
:retry_submodule_update
set /a retry_submodule_update+=1
git submodule update --checkout --force --recursive
if %retry_submodule_update% gtr 10 exit !errorlevel!
if errorlevel 1 goto :retry_submodule_update

cmake -DCMAKE_GENERATOR_PLATFORM=x64 -DLSQUIC_SHARED_LIB=ON -DBUILD_SHARED_LIBS=ON -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=c:/tools/vcpkg/scripts/buildsystems/vcpkg.cmake -DBORINGSSL_DIR=%cd%\boringssl -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON .

msbuild /m src\liblsquic\lsquic.vcxproj
if errorlevel 1 exit !errorlevel!
msbuild /m tests\build-tests.vcxproj
if errorlevel 1 exit !errorlevel!

