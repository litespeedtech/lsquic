for /f "usebackq delims=#" %%a in (`"%programfiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -latest -property installationPath`) do call "%%~a\VC\Auxiliary\Build\vcvars64.bat"

msbuild /m RUN_TESTS.vcxproj /v:n
set testserror=%errorlevel%

"C:\msys64\usr\bin\ldd.exe" "tests\Debug\test_cubic.exe"

if %testserror% neq 0 exit %testserror%

msbuild /m bin\perf_server.vcxproj /v:n
if errorlevel 1 exit !errorlevel!
msbuild /m bin\perf_client.vcxproj /v:n
if errorlevel 1 exit !errorlevel!

start "" /B bin\Debug\perf_server -L notice -s ::1:8443 -c localhost,tests/localhost.pem,tests/localhost.key

bin\Debug\perf_client -L info -s ::1:8443 -p 104857600:104857600

tskill perf_server

