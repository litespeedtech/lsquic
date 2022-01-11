for /f "usebackq delims=#" %%a in (`"%programfiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -latest -property installationPath`) do call "%%~a\VC\Auxiliary\Build\vcvars64.bat"

start "" /b cmd /c "(timeout /t 600 /nobreak && taskkill /t /f /fi "imagename eq test_*")>nul"

msbuild /m RUN_TESTS.vcxproj /v:n
set testserror=%errorlevel%

"C:\msys64\usr\bin\ldd.exe" "tests\Debug\test_cubic.exe"

msbuild /m bin\perf_server.vcxproj /v:n
if errorlevel 1 goto :after_perf_test
msbuild /m bin\perf_client.vcxproj /v:n
if errorlevel 1 goto :after_perf_test

start "" /B bin\Debug\perf_server -L notice -s ::1:8443 -c localhost,tests/localhost.pem,tests/localhost.key

bin\Debug\perf_client -L info -s ::1:8443 -p 104857600:104857600

tskill perf_server

:after_perf_test
if %testserror% neq 0 exit %testserror%