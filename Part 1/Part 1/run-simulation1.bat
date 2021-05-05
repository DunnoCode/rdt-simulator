echo off

REM Author - atctam
REM Version 1.0 - tested on Windows 10 Pro 10.0.16299

REM Check no. of arguments
if %1.==. (
	echo Not enough input arguments. 
	echo Usage: %0 "filename"
	goto :END
)
if not %2.==. (
	echo Too many input arguments.
	echo Usage: %0 "filename"
	goto :END
)

REM Star the simulation
echo Start the server
start cmd /k python test-server1.py localhost

REM pause for 1 second
timeout /t 1 /nobreak >nul

echo Start the client
start cmd /k python test-client1.py localhost %1

:END
