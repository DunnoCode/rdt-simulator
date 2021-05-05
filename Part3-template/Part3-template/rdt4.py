#!/usr/bin/python3
"""Implementation of RDT4.0

functions: rdt_network_init, rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Date and version: 09/04/2021, Version 1
Development platform: Win10
Python version: Python 3.9.2
"""

import socket
import random
import struct
import select

#some constants
PAYLOAD = 1000		#size of data payload of each packet
CPORT = 100			#Client port number - Change to your port number
SPORT = 200			#Server port number - Change to your port number
TIMEOUT = 0.05		#retransmission timeout duration
TWAIT = 10*TIMEOUT 	#TimeWait duration

#store peer address info
__peeraddr = ()		#set by rdt_peer()
#define the error rates and window size
__LOSS_RATE = 0.0	#set by rdt_network_init()
__ERR_RATE = 0.0
__W = 1

#sequence number
__Packet_Num = 0
__ACK_Num = 0
__ACK_over_255 = 0

#internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
	"""This function is for simulating packet loss or corruption in an unreliable channel.

	Input arguments: Unix socket object, peer address 2-tuple and the message
	Return  -> size of data sent, -1 on error
	Note: it does not catch any exception
	"""
	global __LOSS_RATE, __ERR_RATE
	if peer_addr == ():
		print("Socket send error: Peer address not set yet")
		return -1
	else:
		#Simulate packet loss
		drop = random.random()
		if drop < __LOSS_RATE:
			#simulate packet loss of unreliable send
			print("WARNING: udt_send: Packet lost in unreliable layer!!")
			return len(byte_msg)

		#Simulate packet corruption
		corrupt = random.random()
		if corrupt < __ERR_RATE:
			err_bytearr = bytearray(byte_msg)
			pos = random.randint(0,len(byte_msg)-1)
			val = err_bytearr[pos]
			if val > 1:
				err_bytearr[pos] -= 2
			else:
				err_bytearr[pos] = 254
			err_msg = bytes(err_bytearr)
			print("WARNING: udt_send: Packet corrupted in unreliable layer!!")
			return sockd.sendto(err_msg, peer_addr)
		else:
			return sockd.sendto(byte_msg, peer_addr)

def __udt_recv(sockd, length):
	"""Retrieve message from underlying layer

	Input arguments: Unix socket object and the max amount of data to be received
	Return  -> the received bytes message object
	Note: it does not catch any exception
	"""
	(rmsg, peer) = sockd.recvfrom(length)
	return rmsg

def __IntChksum(byte_msg):
	"""Implement the Internet Checksum algorithm

	Input argument: the bytes message object
	Return  -> 16-bit checksum value
	Note: it does not check whether the input object is a bytes object
	"""
	total = 0
	length = len(byte_msg)	#length of the byte message object
	i = 0
	while length > 1:
		total += ((byte_msg[i+1] << 8) & 0xFF00) + ((byte_msg[i]) & 0xFF)
		i += 2
		length -= 2

	if length > 0:
		total += (byte_msg[i] & 0xFF)

	while (total >> 16) > 0:
		total = (total & 0xFFFF) + (total >> 16)

	total = ~total

	return total & 0xFFFF

######################################################################################################################
# Reusing the appending internal function in part2 

def __make_packet(seqNum, payloadLength, data):
	# compose the header
	# The header should consists of four components in the following order:
	# struct {
	#	unsigned char type 	ACK = 11, Data = 12		1 bytes
	#   unsigned seq# 	0 or 1						1 bytes 
	#	unsigned short checksum						2 bytes
	#	unsigned short payload length				2 bytes
	# }
	# Noted that packet is 12 
	# https://docs.python.org/3/library/struct.html
	header_format = struct.Struct('BBHH')
	pseudo_header = header_format.pack(12, seqNum, 0, payloadLength)
	byte_msg = pseudo_header + data
	checksum = __IntChksum(byte_msg)
	header = header_format.pack(12, seqNum, checksum, payloadLength)
	return (header + data)

def __make_ACK(seqNum):
	# compose the header 
	# The header structure is same as the __make_packet
	# Noted that the type will be 11 as ACK and the payload length will be 0
	header_format = struct.Struct('BBHH')
	pseudo_header = header_format.pack(11, seqNum, 0, socket.htons(0)) + b''
	byte_msg = pseudo_header
	checksum = __IntChksum(byte_msg)
	header = header_format.pack(11, seqNum, checksum, socket.htons(0)) + b''
	return header
def __get_header(header):
	header_format = struct.Struct('BBHH')
	return header_format.unpack(header)

def __no_corruption(recv_type, seq, checksum, payload_length, data):
	header_format = struct.Struct('BBHH')
	pseudo_header = header_format.pack(recv_type, seq, 0, payload_length)
	byte_msg = pseudo_header + data
	temp_checksum = __IntChksum(byte_msg)
	if (temp_checksum == checksum):
		return True
	else:
		return False

# appending new internal function for part 3
def __packet_send(packet_list, sockd):
	seq = __Packet_Num
	for i in range(len(packet_list)):
		try:
			length = __udt_send(sockd, __peeraddr, packet_list[i])
			print("rdt_send: Packet %d with message size %d" % (seq, length))
			seq += 1
		except socket.error as emsg:
			print("Socket send error: ", emsg)
			return -1

def __packet_retransmit(packet_list, sockd):
	seq = __Packet_Num
	for i in range(len(packet_list)):
		try:
			length = __udt_send(sockd, __peeraddr, packet_list[i])
			print("rdt_send: Timeout!! Retransmit the packet %d agian" %seq)
			seq = seq + 1
		except socket.error as emsg:
			print("Socket send error: ", emsg)
			return -1

def __packet_seq(times):
	number = __Packet_Num
	start = []
	for x in range(times):
		if number == 256:
			number = 0
		start.append(number)
		number += 1
	return start

def __pop_packet_seq(target, start, packet_list):
	while(True):
		answer = start.pop(0)
		packet_list.pop(0)
		if answer == target:
			return (start, packet_list)

def __check_retramsmit(target):
	minimum = __ACK_Num - __W
	range_list = []
	#build range list 
	if ((minimum < 0) & (__ACK_over_255 > 0)):
		print("cnmb")
		for i in range(__W):
			if (minimum + i < 0):
				range_list.append((minimum + i + 256))
			else:
				range_list.append((minimum + i))
	elif((minimum < 0) & (__ACK_over_255 == 0)):
		range_list = [i for i in range(__ACK_Num)]
	else:
		for i in range(__W):
			if (minimum + i > 255):
				range_list.append(minimum + i - 256)
			else:
				range_list.append(minimum + i)
	if(target in range_list):
		return True
	else:
		return False

#These are the functions used by appliation

def rdt_send(sockd, byte_msg):
	"""Application calls this function to transmit a message (up to
	W * PAYLOAD bytes) to the remote peer through the RDT socket.

	Input arguments: RDT socket object and the message bytes object
	Return  -> size of data sent on success, -1 on error

	Note: (1) This function will return only when it knows that the
	whole message has been successfully delivered to remote process.
	(2) Catch any known error and report to the user.
	"""
	######## Your implementation #######
	global PAYLOAD, __peeraddr, __Packet_Num
	packet_list = []
	message = 0
	size = 0
	enter = __Packet_Num
	cut = 0
	rest = len(byte_msg)
	# Building a list of packet and recording the number of message and total size
	while(message != __W):
		if (rest > PAYLOAD):
			msg = byte_msg[cut:(cut + PAYLOAD)]
			packet = __make_packet(enter, len(msg), msg)
			packet_list.append(packet)
			size += len(msg)
			enter += 1
			cut += PAYLOAD
			rest -= PAYLOAD
			if enter == 256:
				enter = 0
			message = message + 1
			print(message)
		else:
			msg = byte_msg[cut:]
			packet = __make_packet(enter, len(msg), msg)
			packet_list.append(packet)
			size += len(msg)
			message = message + 1
			enter += 1
			if enter == 256:
				enter = 0
			break
	#reset seq number 
	start = __packet_seq(message)
	# Sending all the packet out 
	__packet_send(packet_list, sockd)
	# create a RList
	# Setting the time interval Reusing part of code from part2 
	while(True):
		RList = [sockd]
		Rready, WReady, EReady = select.select(RList,[],[],TIMEOUT)
		if Rready:
			rmsg =  __udt_recv(sockd, PAYLOAD + 6)
			if rmsg:
				header = rmsg[:6]
				data = rmsg[6:]
				(recv_type, seq, checksum, payload_length) = __get_header(header)
				#check the packet has corrupted or not
				if (__no_corruption(recv_type, seq, checksum, payload_length, data)):
					#check is ack or packet  
					if (recv_type == 11):
						if (seq == start[0]):
							print("rdt_send: Received the expected ACK with seqNo: %d" % seq)
							__Packet_Num = __Packet_Num + 1
							print("Packet %d is successfully sent" %seq)
							#check the packet list is all send out or not
							(start, packet_list) = __pop_packet_seq(seq, start, packet_list)
							__Packet_Num = seq + 1
							if __Packet_Num == 256:
								__Packet_Num = 0
							if(start == []):
								print("rdt_send: Successfully Send %d message(s) of total size %d" % (message, size))
								return size
						elif (seq not in start):
							# ack out of sending packet range
							# do nothing
							print("do nothing %d" % seq)
						else:
							# cumulative acknowledgement 
							print("rdt_send: Received an ACK with seqNO: %d" %seq)
							print("rdt_send: All segments from %d to %d are acknowledged" %(__Packet_Num, seq))
							(start, packet_list) = __pop_packet_seq(seq, start, packet_list)
							__Packet_Num = seq + 1
							if __Packet_Num >= 256:
								__Packet_Num = __Packet_Num - 256
							if(start == []):
								print("rdt_send: Successfully Send %d message(s) of total size %d" % (message, size))
								return size

					else:
						# received a data packet 
						# As the previous ack is loss and peer is starting to retransmit the data 
						if(__check_retramsmit(seq)):
							print("rdt_send: Received a retransmission DATA packet from peer!!")
							ack = __make_ACK(seq)
							try:
								__udt_send(sockd, __peeraddr, ack)
							except socket.error as emsg:
								print("Socket send error: ", emsg)
								return -1
							print("rdt_send: Retransmit the ACK pakcet")
						__packet_retransmit(packet_list, sockd)
						continue
				else:
					# received a corrupted packet
					print("rdt_send: Received a corrupted packet")
					__packet_retransmit(packet_list, sockd)
					continue
		#Time out and retransmit all the packet in packet list
		else:
			print("retransmit the data again start from %d" % __Packet_Num)
			__packet_retransmit(packet_list, sockd)
			continue
	













def rdt_recv(sockd, length):
	"""Application calls this function to wait for a message from the
	remote peer; the caller will be blocked waiting for the arrival of
	the message. Upon receiving a message from the underlying UDT layer,
    the function returns immediately.

	Input arguments: RDT socket object and the size of the message to
	received.
	Return  -> the received bytes message object on success, b'' on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	# Reusing part 2 code
	global __ACK_Num, __peeraddr, __ACK_over_255
	while(True):
		try:
			rmsg = __udt_recv(sockd, length + 6)
		except socket.error as emsg:
			print("Socket recv error: ", emsg)
			return b''
		print("rdt_recv: Received a message of size %d" % len(rmsg))
		# check is a package or not
		header = rmsg[:6]
		data = rmsg[6:]
		(recv_type, seq, checksum, payload_length) = __get_header(header)
		# check the packet is corrupted or not
		if (__no_corruption(recv_type, seq, checksum, payload_length, data)):
			print("data is not corrupted")
			# check the packet is data or ack 
			if (recv_type == 12):
				# this is correct data
				if (seq == __ACK_Num):
					print("rdt_recv: Got an expected packet %d" % seq)
					ack = __make_ACK(seq)
					try:
						__udt_send(sockd, __peeraddr, ack)
					except socket.error as emsg:
						print("Socket send error: ", emsg)
						return -1
					__ACK_Num = __ACK_Num + 1
					if (__ACK_Num == 256):
						__ACK_Num = 0
						__ACK_over_255 += 1
					return data
				elif (__check_retramsmit(seq)):
					print("rdt_recv: Received a retransmission DATA packet %d from peer!!" % seq)
					ack = __make_ACK(seq)
					try:
						__udt_send(sockd, __peeraddr, ack)
						print("rdt_recv: Retransmit the ACK packet")
					except socket.error as emsg:
						print("Socket send error: ", emsg)
						return -1
			else:
				# this is ack
				print("receive a ack")
		else:
			# let the sender time out and retransmit
			continue









































def rdt_close(sockd):
	"""Application calls this function to close the RDT socket.

	Input argument: RDT socket object

	Note: (1) Catch any known error and report to the user.
	(2) Before closing the RDT socket, the reliable layer needs to wait for TWAIT
	time units before closing the socket.
	"""
	######## Your implementation #######
	while(True):
		RList = [sockd]
		Rready, WReady, EReady = select.select(RList,[],[],TWAIT)
		if Rready:
			rmsg =  __udt_recv(sockd, PAYLOAD + 6)
			if rmsg:
				header = rmsg[:6]
				data = rmsg[6:]
				(recv_type, seq, checksum, payload_length) = __get_header(header)
				if (__no_corruption(recv_type, seq, checksum, payload_length, data)):
					#check the packet is data or not
					if(recv_type == 12):
						print("hehexd")
						print("data is not corrupted")
						ack = __make_ACK(seq)
						try:
							__udt_send(sockd, __peeraddr, ack)
						except socket.error as err_msg:
							print(str(err_msg))
							return -1
		else:
			# Time out
			try:
				print("time out")
				sockd.close()
				return
			except socket.error as emsg:
				print("Socket close error: ", emsg)










































######################################################################################################################

def rdt_network_init(drop_rate, err_rate, W):
	"""Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability, packet corruption probability and Window size
	"""
	random.seed()
	global __LOSS_RATE, __ERR_RATE, __W
	__LOSS_RATE = float(drop_rate)
	__ERR_RATE = float(err_rate)
	__W = int(W)
	print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE, "\tWindow size:", __W)

def rdt_socket():
	"""Application calls this function to create the RDT socket.

	Null input.
	Return the Unix socket object on success, None on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	#Reusing part 1 code
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
	######## Your implementation #######
	#Reusing part 1 code
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
	######## Your implementation #######
	#Reusing part 1 code
	global __peeraddr
	__peeraddr = (peer_ip, port)
