@echo off
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
"C:\msys64\ucrt64\bin\cmake.exe" %*
exit /b %ERRORLEVEL%
