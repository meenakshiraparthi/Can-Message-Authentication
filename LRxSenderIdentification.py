#!/usr/bin/python3
#
# Use this cript to automaticaly configure the vcan0 device to be able to send can-fd messages
#
import os #to execute linux commands
import can #for can utilities
import time ##for sleep commands
import hashlib ##hash library
from Crypto.Cipher import AES
import binascii
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
def verifyCMAC(key,IV,message_bytes):
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

def genDecryption(key,IV,ciphertext):
	ciphertext = bytes.fromhex(ciphertext)
	print("Ciphertext is ",ciphertext)
	cipher = AES.new(key.encode(),AES.MODE_CBC,IV.encode())
	ciphertext = cipher.decrypt(ciphertext)
	myMes = ciphertext.decode()
	print("The Message is: ", myMes)
	return ciphertext

IV = "0000000000000000"
key = "0000000000000000"
key1 = "0"
key2 = "0"
key3 = "0"
hash_verifier = 0
#n = input("Enter the no.of values in hash chain")
n = int(10)
m = int(1)
j = n-2
encryptionKey = "0"
macKey = "0"
keycopy = "0000000000000000"
stringArray = []
for i in range (0, n) :
	hash = hashlib.sha256(keycopy.encode()).hexdigest()
	hash = hash[:3]
	stringArray.append(hash)
	keycopy = hash

print(stringArray)
print(stringArray[n-1], "is the public key")
# receive custom messages using python
try:
	while True:
		msg = bus.recv()
		message = binascii.hexlify(msg.data);
		message = str(message)[2:18]
		message_arbitration_id = msg.arbitration_id
		#print(message)
		message_arbitration_id0 = hex(message_arbitration_id)[2:]
		#print(message_arbitration_id0)
		message_arbitration_id1 = message[:m]
		#print(message_arbitration_id1)
		message_arbitration_id = message_arbitration_id0 + message_arbitration_id1
		print(message_arbitration_id)
		#print(message_arbitration_id)
		if len(message_arbitration_id) < 3:
			message_arbitration_id = message_arbitration_id.zfill(3)		
		print(message_arbitration_id)
		#print(stringArray[j])
		if message_arbitration_id == stringArray[j]:
			print(message_arbitration_id)
			print(stringArray[j])
			print("success")
		else:
			print("failure")
		if j <= 3:

			if j == 3:
				encryptionKey = hashlib.sha1(stringArray[3].encode()).hexdigest()[:16]
				print("the encryption key is ", encryptionKey)
				macKey = hashlib.sha1(encryptionKey.encode()).hexdigest()[:16]
				print("MAC key is ", macKey)
				data = binascii.hexlify(msg.data)
				print("rfeceived data is ", data)
				mac = str(data)[15:18]
				print("received mac is", mac)
				k = str(data)[4:15]
				print("decryption first half ", k)
				macVerifier = verifyCMAC(macKey,IV,k)
				if mac == macVerifier:
					key1 = k
					print("MAC verification success for 1")
				else:
					print("MAC verification failed for 1")

			if j == 2:
				data = binascii.hexlify(msg.data)
				print("rfeceived data is ", data)
				mac = str(data)[15:18]
				print("received mac is", mac)
				k = str(data)[4:15]
				print("decryption first half ", k)
				macVerifier = verifyCMAC(macKey,IV,k)
				if mac == macVerifier:
					key2 = k
					print("MAC verification success for 2")
				else:
					print("MAC verification failed for 2")	

			if j == 1:
				data = binascii.hexlify(msg.data)
				print("rfeceived data is ", data)
				mac = str(data)[15:18]
				print("received mac is", mac)
				k = str(data)[4:15]
				print("decryption first half ", k)
				macVerifier = verifyCMAC(macKey,IV,k)
				k = str(data)[5:15]
				if mac == macVerifier:
					key3 = k
					print("MAC verification success for 3")
					keymessage = key1 + key2 + key3
					print("the final cipher text for decryption is ", keymessage)
					key = genDecryption(encryptionKey,IV,keymessage)
					print("the new key is ", key)
					j = n-1
					stringArray = []
					for i in range (0, n) :
						hash = hashlib.sha256(keycopy.encode()).hexdigest()
						hash = hash[:3]
						stringArray.append(hash)
						keycopy = hash

					print(stringArray)
					print(stringArray[n-1], "is the public key")
					
				else:
					print("MAC verification failed for 3")	
		
		j = j-1	
				
				
				
								
				
			
			 

except KeyboardInterrupt:
	#Catch keyboard interrupt
	os.system("sudo /sbin/ip link set can0 down")
	print('\n\rInterrupted Reception')
