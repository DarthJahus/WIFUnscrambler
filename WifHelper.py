import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import os
import re
import struct

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58encode(n):
	result = ''
	while n > 0:
		result = b58[n%58] + result
		n /= 58
	return result


def base256decode(s):
	result = 0
	for c in s:
		result = result * 256 + ord(c)
	return result


def countLeadingChars(s, ch):
	count = 0
	for c in s:
		if c == ch:
			count += 1
		else:
			break
	return count


# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
	s = chr(version) + payload
	checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
	result = s + checksum
	leadingZeros = countLeadingChars(result, '\0')
	return 'D' * leadingZeros + base58encode(base256decode(result))


def privateKeyToWif(key_hex):
	return base58CheckEncode(0x04, key_hex.decode('hex'))


def privateKeyToPublicKey(s):
	sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
	vk = sk.verifying_key
	return ('\04' + sk.verifying_key.to_string()).encode('hex')


def pubKeyToAddr(s):
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
	return base58CheckEncode(30, ripemd160.digest()) # 30 = doge, 0 = BTC


def keyToAddr(s):
	return pubKeyToAddr(privateKeyToPublicKey(s))


if __name__ == "__main__":
	private_key = os.urandom(32).encode('hex')
	# You can verify the values on http://brainwallet.org/
	print "Secret Exponent (Uncompressed) : %s " % private_key
	print "Private Key (WIF) : %s " % privateKeyToWif(private_key)
	print "Address           : %s " % keyToAddr(private_key)
