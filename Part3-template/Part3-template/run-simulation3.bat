echo off

REM Author - atctam
REM Version 1.0 - tested on Windows 10 Pro 10.0.16299

REM Check no. of arguments
if %4.==. (
	echo Not enough input arguments. 
	echo Usage: %0 "filename" "drop rate" "error rate" "Window size"
	goto :END
)
if not %5.==. (
	echo Too many input arguments.
	echo Usage: %0 "filename" "drop rate" "error rate" "Window size"
	goto :END
)

REM Star the simulation
echo Start the server
start cmd /k python test-server3.py localhost %2 %3 %4

REM pause for 1 second
timeout /t 1 /nobreak >nul

echo Start the client
start cmd /k python test-client3.py localhost %1 %2 %3 %4

:END
