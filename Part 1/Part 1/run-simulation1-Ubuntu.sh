#!/bin/sh

## Author - atctam
## Version 1.0 - tested on Ubuntu 16.04.3 LTS

# Check no. of input arguments
if [ $# -ne 1 ]
then
	echo "USAGE: $0 'filename'"
	exit
fi

# Start the simulation
echo "Start the server"
gnome-terminal --command="bash -c \"python3 test-server1.py localhost; exec bash\" "

# Pause for 1 second
sleep 1

echo "Start the client"
gnome-terminal --command="bash -c \"python3 test-client1.py localhost '$1'; exec bash\" "

