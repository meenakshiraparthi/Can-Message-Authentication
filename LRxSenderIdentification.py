#!/usr/bin/python3
#
# Use this cript to automaticaly configure the vcan0 device to be able to send can-fd messages
#
import os #to execute linux commands
import can #for can utilities
import time ##for sleep commands
import hashlib ##hash library
from Crypto.Cipher import AES
try:
	#os.system("sudo /sbin/ip link set vcan0 down type vcan")
	#os.system("sudo /sbin/ip link set vcan0 up type vcan")
	time.sleep(0.1)		
	bus = can.interface.Bus(channel='vcan2', bustype='socketcan_native',fd = True)	

	
except OSError:
	print('ERROR with virtual CAN device')
	print('Make sure you enalbed the vcan device using modprobe!!')
	print('Make sure you added a new virtual can device vcan1!!')
	print('If you are using for FD make sure to set the mtu 72 falg!!')
	exit()
#----verification of mac 
def verifyCMAC(key,IV,message_bytes,receivedCMAC):
	message  = message_bytes
	IV += bytes([0]) * 8
	message += bytes([0]) * 8
	cipher = AES.new(key.encode(), AES.MODE_CBC, IV)
	ciphertext = cipher.encrypt(message)
	print("received CMAC :",receivedCMAC)
	print("generated CMAC :",ciphertext)
	if receivedCMAC in ciphertext:
		print("Verification Success")
		return "SUCCESS"
	else:
		print("Verification failed")
		return "FAIL"

def genDecryption(key,IV,message_bytes)

IV = "0000000000000000"
key = "0000000000000000"
hash_verifier = 0
#n = input("Enter the no.of values in hash chain")
n = int(6)
m = int(2)
j = n-2
keycopy = "0000000000000000"
stringArray = []
for i in range (0, n) :
	hash = hashlib.sha256(keycopy.encode()).hexdigest()
	hash = hash[:4]
	stringArray.append(hash)
	keycopy = hash

print(stringArray)
print(stringArray[n-1], "is the public key")
# receive custom messages using python
try:
	while True:
		msg = bus.recv()
		message_arbitration_id = msg.arbitration_id
		message_arbitration_id0 = hex(message_arbitration_id)[2:]
		#print(message_arbitration_id0)
		message_arbitration_id1 = (bytes(msg.data).decode())[:m]
		#print(message_arbitration_id1)
		message_arbitration_id = message_arbitration_id0 + message_arbitration_id1
		#print(message_arbitration_id)
		if len(message_arbitration_id) < 4:
			message_arbitration_id = message_arbitration_id.zfill(4)		
		#print(message_arbitration_id)
		#print(stringArray[j])
		if message_arbitration_id == stringArray[j]:
			print(message_arbitration_id)
			print(stringArray[j])
			print("success")
			j = j-1
		else:
			print("failure")
			j = j-1

except KeyboardInterrupt:
	#Catch keyboard interrupt
	os.system("sudo /sbin/ip link set can0 down")
	print('\n\rInterrupted Reception')
