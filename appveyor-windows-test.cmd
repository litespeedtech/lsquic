msbuild /m RUN_TESTS.vcxproj
if errorlevel 1 exit !errorlevel!

msbuild /m perf_server.vcxproj
if errorlevel 1 exit !errorlevel!
msbuild /m perf_client.vcxproj
if errorlevel 1 exit !errorlevel!

.\bin\perf_server -L notice -s ::1:8443 -c localhost,tests/localhost.pem,tests/localhost.key

echo Started @ %time%
.\bin\perf_client -L info -s ::1:8443 -p 104857600:104857600
echo Finished @ %time%

tskill perf_server
