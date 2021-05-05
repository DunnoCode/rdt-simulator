#!/bin/sh

## Author - atctam
## Version 1.0 - tested on macOS High Sierra version 10.13.2

CPATH="`pwd`"


# Check no. of input arguments
if [ $# -ne 1 ]
then
	echo "USAGE: $0 'filename'"
	exit
fi

# Start the simulation
echo "Start the server"
osascript <<-EOD
	tell application "Terminal"
		activate
		tell window 1
			do script "cd '$CPATH'; python3 test-server1.py localhost"
		end tell
	end tell
EOD

# Pause for 1 second
sleep 1

echo "Start the client"
osascript <<-EOD
	tell application "Terminal"
		activate
		tell window 1
			do script "cd '$CPATH'; python3 test-client1.py localhost '$1'"
		end tell
	end tell
EOD
