#!/usr/bin/python3
"""Implementation of RDT1.0

functions: rdt_network_init(), rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()
"""

import socket

#some constants
PAYLOAD = 1000		#size of data payload of the RDT layer
CPORT = 59079		#Client port number - Change to your port number
SPORT = 59080		#Server port number - Change to your port number

#store peer address info
__peeraddr = ()		#set by rdt_peer()


#internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
	"""RDT1.0 assume UDP is reliable

	Input arguments: socket object, peer address 2-tuple and the message
	Return  -> size of data sent on success, -1 on error
	Note: it does not catch any exception
	"""
	if peer_addr == ():
		print("Socket send error: Peer address not set yet")
		return -1
	else:
		return sockd.sendto(byte_msg, peer_addr)

def __udt_recv(sockd, length):
	"""RDT1.0 assume UDP is reliable

	Input arguments: socket object and the max amount of data to be received
	Return  -> the received bytes message object
	Note: it does not catch any exception
	"""
	(rmsg, peer) = sockd.recvfrom(length)
	return rmsg

#These are the functions used by appliation
def rdt_network_init():
	"""Application calls this function to set properties of underlying network.

    A dummy function for rdt1.0
	"""
	print("Drop rate: 0.0\tError rate: 0.0")

def rdt_socket():
	"""Application calls this function to create the RDT socket.

	Null input.
	Return the Unix socket object on success, None on error

	Note: Catch any known error and report to the user.
	"""
	try:
		sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as emsg:
		print("Socket creation error: ", emsg)
		return None
	return sd

def rdt_bind(sockd, port):
	"""Application calls this function to specify the port number
	used by itself and assigns them to the RDT socket.

	Input arguments: RDT socket object and port number
	Return	-> 0 on success, -1 on error

	Note: Catch any known error and report to the user.
	"""
	try:
		sockd.bind(("",port))
	except socket.error as emsg:
		print("Socket bind error: ", emsg)
		return -1
	return 0

def rdt_peer(peer_ip, port):
	"""Application calls this function to specify the IP address
	and port number used by remote peer process.

	Input arguments: peer's IP address and port number
	"""
	global __peeraddr
	__peeraddr = (peer_ip, port)

def rdt_send(sockd, byte_msg):
	"""Application calls this function to transmit a message to
	the remote peer through the RDT socket.

	Input arguments: RDT socket object and the message bytes object
	Return  -> size of data sent on success, -1 on error

	Note: Make sure the data sent is not longer than the maximum PAYLOAD
	length. Catch any known error and report to the user.
	"""
	global PAYLOAD, __peeraddr
	print(len(byte_msg))
	if (len(byte_msg) > PAYLOAD):
		msg = byte_msg[0:PAYLOAD]
	else:
		msg = byte_msg
	try:
		length = __udt_send(sockd, __peeraddr, msg)
	except socket.error as emsg:
		print("Socket send error: ", emsg)
		return -1
	print("rdt_send: Sent one message of size %d" % length);
	return length

def rdt_recv(sockd, length):
	"""Application calls this function to wait for a message from the
	remote peer; the caller will be blocked waiting for the arrival of
	the message.

	Input arguments: RDT socket object and the size of the message to
	received.
	Return  -> the received bytes message object on success, b'' on error

	Note: Catch any known error and report to the user.
	"""
	try:
		rmsg = __udt_recv(sockd, length)
	except socket.error as emsg:
		print("Socket recv error: ", emsg)
		return b''
	print("rdt_recv: Received a message of size %d" % len(rmsg))
	return rmsg

def rdt_close(sockd):
	"""Application calls this function to close the RDT socket.

	Input argument: RDT socket object

	Note: Catch any known error and report to the user.
	"""
	try:
		sockd.close()
	except socket.error as emsg:
		print("Socket close error: ", emsg)

