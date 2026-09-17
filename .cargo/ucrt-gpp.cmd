@echo off
set "PATH=C:\msys64\ucrt64\bin;%PATH%"
"C:\msys64\ucrt64\bin\g++.exe" %*
exit /b %ERRORLEVEL%
