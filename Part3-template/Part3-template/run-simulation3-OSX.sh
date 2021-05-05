#!/bin/sh

## Author - atctam
## Version 1.0 - tested on macOS High Sierra version 10.13.2

CPATH="`pwd`"


# Check no. of input arguments
if [ $# -ne 4 ]
then
	echo "USAGE: $0 'filename' 'drop rate' 'error rate' 'Window size'"
	exit
fi

# Start the simulation
echo "Start the server"
osascript <<-EOD
	tell application "Terminal"
		activate
		tell window 1
			do script "cd '$CPATH'; python3 test-server3.py localhost '$2' '$3' '$4'"
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
			do script "cd '$CPATH'; python3 test-client3.py localhost '$1' '$2' '$3' '$4'"
		end tell
	end tell
EOD
