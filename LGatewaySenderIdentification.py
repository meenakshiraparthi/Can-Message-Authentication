#!/usr/bin/python3
#
# Use this cript to automaticaly configure the vcan0 device to be able to send can-fd messages
#
import os #to execute linux commands
import can #for can utilities
import time ##for sleep commands
import hashlib ##hash library

try:
	#os.system("sudo /sbin/ip link set vcan0 down type vcan")
	#os.system("sudo /sbin/ip link set vcan0 up type vcan")
	time.sleep(0.1)		
	bus = can.interface.Bus(channel='vcan1', bustype='socketcan_native',fd = True)	

	
except OSError:
	print('ERROR with virtual CAN device')
	print('Make sure you enalbed the vcan device using modprobe!!')
	print('Make sure you added a new virtual can device vcan1!!')
	print('If you are using for FD make sure to set the mtu 72 falg!!')
	exit()



key = "0000000000000000"
hash_verifier = c4cd
m = int(1)
# receive custom messages using python
try:
	while True:
		msg = bus.recv()	# Wait until a message is received.
		message_arbitration_id = msg.arbitration_id
		#print(message_arbitration_id)
		#message_data = bytes(msg.data)
		#if message_arbitration_id == 0x000e:
			#message_arbitration_id = hex(message_arbitration_id)
			#print(message_arbitration_id)
		a = bytes(msg.data).decode()
		b = a[2:2]
		if b == 8 :
			print(hash_verifier)
			message_arbitration_id0 = hex(message_arbitration_id)[2:]
			#print(message_arbitration_id0)
			message_arbitration_id1 = (bytes(msg.data).decode())[:m]
			#print(message_arbitration_id1)
			message_arbitration_id = message_arbitration_id0 + message_arbitration_id1
			#print(message_arbitration_id)
			if len(message_arbitration_id) < 3:
				message_arbitration_id = message_arbitration_id.zfill(3)
			print(message_arbitration_id)
			hash = hashlib.sha256(message_arbitration_id.encode()).hexdigest()
			#print(hash)
			verifier = hash[:3]
			print(verifier)
	
			if verifier == hash_verifier :
				hash_verifier = a[3:6]
			else:
				print("wrong public key")
			#print(hash_verifier)
			#print("---------------")
		else:
			print(hash_verifier)
			message_arbitration_id0 = hex(message_arbitration_id)[2:]
			#print(message_arbitration_id0)
			message_arbitration_id1 = (bytes(msg.data).decode())[:m]
			#print(message_arbitration_id1)
			message_arbitration_id = message_arbitration_id0 + message_arbitration_id1
			#print(message_arbitration_id)
			if len(message_arbitration_id) < 4:
				message_arbitration_id = message_arbitration_id.zfill(4)
			print(message_arbitration_id)
			hash = hashlib.sha256(message_arbitration_id.encode()).hexdigest()
			#print(hash)
			verifier = hash[:4]
			print(verifier)
	
			if verifier == hash_verifier :
				hash_verifier = message_arbitration_id
				print("verification success")
				msg1 = can.Message(arbitration_id= msg.arbitration_id ,is_fd = False, bitrate_switch = False ,data = msg.data, extended_id = True)
				bus.send(msg1)
				time.sleep(0.2)
			else:
				print("verification failed")	
except KeyboardInterrupt:
	#Catch keyboard interrupt
	os.system("sudo /sbin/ip link set can0 down")
	print('\n\rInterrupted Reception')
