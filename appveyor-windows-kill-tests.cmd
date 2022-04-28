@echo off && setlocal
set timeout=0
set /a timeout+=%~1
set elapsed=0

:wait
if not exist killing-tests.tmp goto :eof
timeout /t 1 /nobreak >nul
set /a elapsed+=1
if %elapsed% lss %timeout% goto :wait

:loop
if not exist killing-tests.tmp goto :eof
taskkill /t /f /fi "imagename eq test_*"
timeout /t 5 /nobreak >nul
goto :loop