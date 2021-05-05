#!/usr/bin/python3
"""File transfer client program

This is for testing of the RDT1.0 layer.

"""

import sys
import os
import time
import rdt1 as rdt

def slowdown():
	"""Just slow down the data transfer
		by dummy computation or by sleeping
	"""
	if sys.platform == "win32":
		y = 0
		for i in range(1,10000):
			y += 3
	else:
		time.sleep(0.0001)

def main():

	MSG_LEN = rdt.PAYLOAD	#get the system payload limit

	#Check the number of input arguments
	if len(sys.argv) != 3:
		print("Usage:  "+sys.argv[0]+"  <server IP>  <filename>")
		sys.exit(0)
	#Get the filename
	filename = sys.argv[2]

	#open file
	try:
		fobj = open(filename, 'rb')
	except OSError as emsg:
		print("Open file error: ", emsg)
		sys.exit(0)
	print("Open file successfully")

	#get the file size
	filelength = os.path.getsize(filename)
	print("File bytes are ",filelength)

	#set up the RDT simulation
	rdt.rdt_network_init()

	#create RDT socket
	sockfd = rdt.rdt_socket()
	if sockfd == None:
		sys.exit(0)

    #specify my own IP address & port number
    #if I do not specify, others can not send things to me.
	if rdt.rdt_bind(sockfd, rdt.CPORT) == -1:
		sys.exit(0)

	#specify the IP address & port number of remote peer
	rdt.rdt_peer(sys.argv[1], rdt.SPORT)

	#implement a simple handshaking protocol at the application layer
	#first send the size of the file to server
	osize = rdt.rdt_send(sockfd, str(filelength).encode("ascii"))
	if osize < 0:
		print("Cannot send message1")
		sys.exit(0)
	#then send the filename to server
	osize = rdt.rdt_send(sockfd, filename.encode("ascii"))
	if osize < 0:
		print("Cannot send message2")
		sys.exit(0)
	#now wait for server response
	rmsg = rdt.rdt_recv(sockfd, MSG_LEN)
	if rmsg == b'':
		sys.exit(0)
	elif rmsg == b'ERROR':
		print("Server experienced file creation error.\nProgram terminated.")
		sys.exit(0)
	else:
		print("Received server positive response")

	#start the data transfer
	print("Start the file transfer . . .")
	starttime = time.monotonic()	#record start time
	sent = 0
	while sent < filelength:
		smsg = fobj.read(MSG_LEN)
		if smsg == b'':
			print("EOF is reached!!")
			sys.exit(0)
		osize = rdt.rdt_send(sockfd, smsg)
		if osize > 0:
			sent += osize
		else:
			print("Experienced sending error! Has sent",sent,"bytes of message so far.")
			sys.exit(0)
		slowdown()	#slightly slowdown the transmission

	endtime = time.monotonic()	#record end time
	print("Completed the file transfer.")
	lapsed = endtime - starttime
	print("Total elapse time: %.3f s\tThroughtput: %.2f KB/s" % (lapsed, filelength/lapsed/1000.0))

	#Closing
	fobj.close()
	rdt.rdt_close(sockfd)
	print("Client program terminated")


if __name__ == "__main__":
	main()

