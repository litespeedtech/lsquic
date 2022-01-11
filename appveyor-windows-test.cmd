for /f "usebackq delims=#" %%a in (`"%programfiles(x86)%\Microsoft Visual Studio\Installer\vswhere" -latest -property installationPath`) do call "%%~a\VC\Auxiliary\Build\vcvars64.bat"

echo 1>killing-tests.tmp

:: cmake test timeout doesn't seem to work right on windows?
:: force loop kill all the tests after 10 minutes (600  seconds)
start "" /b cmd /c "(timeout /t 600 /nobreak && call appveyor-windows-kill-tests.cmd)>nul"

msbuild /m RUN_TESTS.vcxproj /v:n

del /q killing-tests.tmp

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
