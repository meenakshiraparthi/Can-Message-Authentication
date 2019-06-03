#!/usr/bin/python3
#
# Use this cript to automaticaly configure the vcan0 device to be able to send can-fd messages
#
import os, binascii #to execute linux commands
import can #for can utilities
import time ##for sleep commands
import hashlib ##hash library
import binascii
from Crypto.Cipher import AES #for crypto operations
from textwrap import wrap
try:
	#os.system("sudo /sbin/ip link set vcan0 down type vcan")
	#os.system("sudo /sbin/ip link set vcan0 up type vcan")
	time.sleep(0.1)		
	bus = can.interface.Bus(channel='vcan0', bustype='socketcan_native',fd = True)	

	
except OSError:
	print('ERROR with virtual CAN device')
	print('Make sure you enalbed the vcan device using modprobe!!')
	print('Make sure you added a new virtual can device vcan0!!')
	print('If you are using for FD make sure to set the mtu 72 falg!!')
	exit()
#---generation of MAC 
def generateCMAC(key,IV,message_bytes):
	message  = message_bytes
	#message += bytes([0]) * 8
	message = message.zfill(16)
	cipher = AES.new(key.encode(), AES.MODE_CBC, IV.encode())
	ciphertext_full = cipher.encrypt(message)
	ciphertext = ciphertext_full.hex()
	ciphertext = ciphertext[:3]
	print("MAC : ",ciphertext)
	#print("Cipher text : ",str(ciphertext).encode())
	#print("Cipher text Lenght :", len(ciphertext))
	return ciphertext
#---encrypting the secrete key
def genEncryption(key,IV,message_bytes):
	message = message_bytes
	#IV += bytes([0]) * 8
	message = message.zfill(16)
	cipher = AES.new(key.encode(), AES.MODE_CBC, IV.encode())
	ciphertext = cipher.encrypt(message)
	#ciphertext = ciphertext_full[:8]
	ciphertext = ciphertext.hex()
	print("Cipher text : ",ciphertext)
	#print("Cipher text : ",str(ciphertext).encode())
	#print("Cipher text Lenght :", len(ciphertext))
	return ciphertext
IV = "0000000000000000"	
n = int(10)
try:

	key = "0000000000000000"
	#n = input("Enter the no.of values in hash chain")
	m = int(1)
	keycopy = "0000000000000000"
	stringArray = []
	for i in range (0, n) :
		hash = hashlib.sha256(keycopy.encode()).hexdigest()
		hash = hash[:3]
		stringArray.append(hash)
		keycopy = hash
	print(stringArray[n-1].encode())
	print (stringArray)
	print("sent")
	#int(hex(stringArray[j]),16
	for j in range(n-2, 3, -1):
		print(j)
		print(stringArray[j])
		#stringArray[j] = "0x" + stringArray[j]
		#print(stringArray[j][:2])
		#print(stringArray[j][2:2+m])
		a = int(stringArray[j][:2],16)
		b = stringArray[j][2:2+m]
		b = b + "0"
		b = bytes.fromhex(b)
		c = binascii.hexlify(b)
		c = str(c)[2:4]
		print(c)
		print(b)
		msg1 = can.Message(arbitration_id= a ,is_fd = False, bitrate_switch = False ,data = b, extended_id = False)
		bus.send(msg1)
		time.sleep(0.2)
		print("sent")

	while(1):
##key management
		key = binascii.b2a_hex(os.urandom(8))
##using SHA1 to get MAC and Encrption keys
		encryptionKey = hashlib.sha1(stringArray[4].encode()).hexdigest()[:16]
		#print(encryptionKey)
		macKey = hashlib.sha1(encryptionKey.encode()).hexdigest()[:16]
		#print(macKey)
		encryptionKeyOutput = genEncryption(encryptionKey,IV,key)
		#print(encryptionKeyOutput)
		encryptionKeyOutput1 = encryptionKeyOutput[:11]
		macKeyOutput1 = generateCMAC(macKey,IV,encryptionKeyOutput1)
		#print(macKeyOutput1)
		#print(encryptionKeyOutput1)
		encryptionKeyOutput2 = encryptionKeyOutput[11:22]
		macKeyOutput2 = generateCMAC(macKey,IV,encryptionKeyOutput2)
		#print(macKeyOutput2)
		#print(encryptionKeyOutput2)
		encryptionKeyOutput3 = encryptionKeyOutput[22:].zfill(11)
		macKeyOutput3 = generateCMAC(macKey,IV,encryptionKeyOutput3)
		#print(macKeyOutput3)
		#print(encryptionKeyOutput3)
		#print("sent1")
##sending first message
		a = int(stringArray[3][:2],16)
		b = stringArray[3][2:2+m]
		b = b + "0"+encryptionKeyOutput1 + macKeyOutput1
		print("message: "+b)		
		b = bytes.fromhex(b)
		c = binascii.hexlify(b);
		c = str(c)[2:18]
		#print("C IS ", c);		
		msg1 = can.Message(arbitration_id= a ,is_fd = False, bitrate_switch = False ,data = b, extended_id = False)
		bus.send(msg1)
		time.sleep(0.2)
		#print("sent1")
##sending second message
		a = int(stringArray[2][:2],16)
		b = stringArray[2][2:2+m]
		b = b + "0" + encryptionKeyOutput2 + macKeyOutput2
		print("message: ", b)
		b = bytes.fromhex(b)
		msg1 = can.Message(arbitration_id= a ,is_fd = False, bitrate_switch = False ,data = b, extended_id = False)
		bus.send(msg1)
		time.sleep(0.2)
		#print("sent2")
##sending third message		
		a = int(stringArray[1][:2],16)
		b = stringArray[1][2:2+m]
		b = b + "0" + encryptionKeyOutput3 + macKeyOutput3
		print("message: ", b)
		b = bytes.fromhex(b)
		msg1 = can.Message(arbitration_id= a ,is_fd = False, bitrate_switch = False ,data = b, extended_id = False)
		bus.send(msg1)
		time.sleep(0.2)
		#sent3
####hash generation
		n = 10
		a = stringArray[0][:2]
		print("public key arbitration id", a)
		a = int(stringArray[0][:2],16)
		b = stringArray[0][2:2+m]
		b = b + "8" + "0"
		stringArray = []
		for i in range (0, n) :
			hash = hashlib.sha256(keycopy.encode()).hexdigest()
			hash = hash[:3]
			stringArray.append(hash)
			keycopy = hash
		#print(stringArray[n-1].encode())
		#print (stringArray)
		b  = b + stringArray[n-1]
		print("public key message: ", b)
		b = bytes.fromhex(b)
		
##sending the public key
		msg1 = can.Message(arbitration_id= a ,is_fd = False, bitrate_switch = False ,data = b, extended_id = False)
		bus.send(msg1)
		time.sleep(0.2)
		for j in range(n-2, 3, -1):
			print(j)
			print(stringArray[j])
			a = int(stringArray[j][:2],16)
			b = stringArray[j][2:2+m]
			b = b + "0"
			b = bytes.fromhex(b)
			print(b)
			msg1 = can.Message(arbitration_id= a ,is_fd = False, bitrate_switch = False ,data = b, extended_id = False)
			bus.send(msg1)
			time.sleep(0.2)
			print("sent")		
		
		
except KeyboardInterrupt:
	#Catch keyboard interrupt
	os.system("sudo /sbin/ip link set can0 down")
	print('\n\rInterrupted Reception')	

