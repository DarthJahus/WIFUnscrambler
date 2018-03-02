# Jahus, 2017-03-01
# Resources:
#     Exemple 9 - https://www.programcreek.com/python/example/81785/ecdsa.SECP256k1
#     https://coinb.in/js/coin.js
#     https://reddit.com/r/dogecoin/comments/7jlwxz/how_to_test_if_the_private_key_is_valid_for_the/


import itertools, base58, binascii, ecdsa
from datetime import datetime
import time
import WifHelper


# The target address of your WIF. This has to be known.
# Keep in mind that a scrambled WIF can generate millions of valid addresses.
target_address = "DDNXza8p38Np4Y3coZ4YU1RhzWieRHmaUf"
# The first parts of the WIF, ordered, if you are sure of them.
# Starts either with Q (compressed) or 6 (uncompressed).
# If you are unsure, set to [""] and add them to middle.
head = ["QCD6"]
# The last parts of the WIF, ordered if you are sure of them.
# If you are unsure, set to [""] and add them to middle.
tail = ["Thw"]
# All the parts that you can't sort.
middle = ["5bjQ", "nZeL", "7KHH", "ThM1", "6KdJ", "JgNW", "pad7", "63zB", "gCMg", "1cje", "AKZ7"]
# Warning, in the case of the address in this script, we are unsure of the head and tail.
# The above values are used as examples.

# The script will show status each number of checked private keys. Set verbosity to define that interval.
# If your CPU is fast, you may want to set that to something higher,
# in a way that you get less messages in a period of time.
verbosity = 1e4


# Convert a WIF key to a private key
def wif2privkey(wif):
	_compressed = False
	decode = base58.b58decode(wif)
	key = decode[0:len(decode)-4]
	key = key[1:]
	if len(key) >= 33 and key[-1] == binascii.unhexlify("01"):
		key = key[:(len(key)-1)]
		_compressed=True
	return {"privkey": binascii.hexlify(key), "compressed": _compressed}


# Convert a private key to a public key using SECP256k1
def newPubkey(h, isCompressed):
	secret = binascii.unhexlify(h)
	order = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1).curve.generator.order()
	p = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1).verifying_key.pubkey.point
	x_str = ecdsa.util.number_to_string(p.x(), order)
	if isCompressed:
		compressed = binascii.hexlify(bytes(chr(2 + (p.y() & 1))) + x_str).decode('ascii')
		return compressed
	else:
		y_str = ecdsa.util.number_to_string(p.y(), order)
		uncompressed = binascii.hexlify(bytes(chr(4)) + x_str + y_str).decode('ascii')
		return uncompressed


# Simple logging
def doLog(text):
	with open(''.join(head) + "-log.txt", 'a') as f:
		f.write(text + '\n')


# Tests and main script
if __name__ == "__main__":
	bTest = False
	if bTest:
		_wif = "QP3quv5BA3vHf6mav9hegrvxGW8AcvrsK7V4VDkLFXwvQjKbgRSE"
		print("WIF= " + _wif)
		print("*1* WIF > privkey")
		_privkey = wif2privkey(_wif)
		print("wif2privkey= " + _privkey["privkey"])
		print("compressed= " + str(_privkey["compressed"]))
		print("*2* privkey > pubkey")
		_pubkey = newPubkey(_privkey["privkey"], _privkey["compressed"])
		print("privkey2pubkey= " + _pubkey)
		print("*3* pubkey > addr")
		_address = WifHelper.pubKeyToAddr(_pubkey)
		print("pubkeyToAddr= " + _address)
	else:
		i = 0
		out = "Started at %s" % datetime.fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%SZ")
		print(out)
		doLog(out)
		for iter in itertools.permutations(middle, len(middle)):
			_wif = ''.join(head) + ''.join(iter) + ''.join(tail)
			# check if WIF => "DDNXza8p38Np4Y3coZ4YU1RhzWieRHmaUf" (target_address)
			try:
				_privkey = wif2privkey(_wif)
				_pubkey = newPubkey(_privkey["privkey"], _privkey["compressed"])
				_address = WifHelper.pubKeyToAddr(_pubkey)
				# print("Found valid address: " + _address)
			except:
				_address = ""
			i+=1
			if i % verbosity == 0: # log / depending on your CPU, make this larger (faster CPU) to reduce verbosity
				out = ("{0} | {1:10,} tested combinations ({2:.2f}%)".format(
					datetime.fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%SZ"),
					i,
					float((float(i)/39916800)*100)
					)
				)
				print(out)
				doLog(out)
			if _address.lower() == target_address.lower():
				out = "Found it: " + _wif
				print(out)
				doLog(out)
				break
		out = ("Tested %i private keys." % i)
		print(out)
		doLog(out)
