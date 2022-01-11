:loop
if not exist killing-tests.tmp goto :eof
taskkill /t /f /fi "imagename eq test_*"
timeout /t 5 /nobreak
goto :loop