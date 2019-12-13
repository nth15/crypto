import time
import EccCore
import binascii
import hashlib
import re
import base64
import time
import random
import hmac
import sys, getopt


code_strings = {
	2: '01',
	10: '0123456789',
	16: '0123456789abcdef',
	32: 'abcdefghijklmnopqrstuvwxyz234567',
	58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
	256: ''.join([chr(x) for x in range(256)])
}

def textToInt(text):
	encoded_text = text.encode('utf-8')
	hex_text = encoded_text.hex()
	int_text = int(hex_text, 16)
	return int_text

def intToText(int_text):
	import codecs
	hex_text = hex(int_text)
	hex_text = hex_text[2:] #remove 0x
	return codecs.decode(codecs.decode(hex_text,'hex'),'ascii')

def get_pubkey_format(pub):
    if isinstance(pub, (tuple, list)): return 'decimal'
    elif len(pub) == 65 and pub[0] == four: return 'bin'
    elif len(pub) == 130 and pub[0:2] == '04': return 'hex'
    elif len(pub) == 33 and pub[0] in [2, 3]: return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in ['02', '03']: return 'hex_compressed'
    elif len(pub) == 64: return 'bin_electrum'
    elif len(pub) == 128: return 'hex_electrum'
    else: raise Exception("Pubkey not in recognized format")

def decode_pubkey(pub, formt=None):
    if not formt: formt = get_pubkey_format(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return (decode(pub[1:33], 256), decode(pub[33:65], 256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33], 256)
        beta = pow(int(x*x*x+A*x+B), int((P+1)//4), int(P))
        y = (P-beta) if ((beta + from_byte_to_int(pub[0])) % 2) else beta
        return (x, y)
    elif formt == 'hex': return (decode(pub[2:66], 16), decode(pub[66:130], 16))
    elif formt == 'hex_compressed':
        return decode_pubkey(safe_from_hex(pub), 'bin_compressed')
    elif formt == 'bin_electrum':
        return (decode(pub[:32], 256), decode(pub[32:64], 256))
    elif formt == 'hex_electrum':
        return (decode(pub[:64], 16), decode(pub[64:128], 16))
    else: raise Exception("Invalid format!")

def decode_privkey(priv,formt=None):
    if not formt: formt = get_privkey_format(priv)
    if formt == 'decimal': return priv
    elif formt == 'bin': return decode(priv, 256)
    elif formt == 'bin_compressed': return decode(priv[:32], 256)
    elif formt == 'hex': return decode(priv, 16)
    elif formt == 'hex_compressed': return decode(priv[:64], 16)
    elif formt == 'wif': return decode(b58check_to_bin(priv),256)
    elif formt == 'wif_compressed':
        return decode(b58check_to_bin(priv)[:32],256)
    else: raise Exception("WIF does not represent privkey")


def decode(string, base):
	if base == 256 and isinstance(string, str):
		string = bytes(bytearray.fromhex(string))
	base = int(base)
	code_string = get_code_string(base)
	result = 0
	if base == 256:
		def extract(d, cs):
			return d
	else:
		def extract(d, cs):
			return cs.find(d if isinstance(d, str) else chr(d))

	if base == 16:
		string = string.lower()
	while len(string) > 0:
		result *= base
		result += extract(string[0], code_string)
		string = string[1:]
	return result

def get_privkey_format(priv):
    if priv.isdigit(): return 'decimal'
    elif len(priv) == 32: return 'bin'
    elif len(priv) == 33: return 'bin_compressed'
    elif len(priv) == 64: return 'hex'
    elif len(priv) == 66: return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return 'wif'
        elif len(bin_p) == 33: return 'wif_compressed'
        else: raise Exception("WIF does not represent privkey")

def get_code_string(base):
	if base in code_strings:
		return code_strings[base]
	else:
		raise ValueError("Invalid base!")

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def changebase(string, frm, to, minlen=0):
	if frm == to:
		return lpad(string, get_code_string(frm)[0], minlen)
	return encode(decode(string, frm), to, minlen)

def bin_dbl_sha256(s):
	bytes_to_hash = from_string_to_bytes(s)
	return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def from_string_to_bytes(a):
	return a if isinstance(a, bytes) else bytes(a, 'utf-8')


def lpad(msg, symbol, length):
	if len(msg) >= length:
		return msg
	return symbol * (length - len(msg)) + msg

def encode(val, base, minlen=0):
	base, minlen = int(base), int(minlen)
	code_string = get_code_string(base)
	result_bytes = bytes()
	while val > 0:
		curcode = code_string[val % base]
		result_bytes = bytes([ord(curcode)]) + result_bytes
		val //= base

	pad_size = minlen - len(result_bytes)

	padding_element = b'\x00' if base == 256 else b'1' \
		if base == 58 else b'0'
	if (pad_size > 0):
		result_bytes = padding_element*pad_size + result_bytes

	result_string = ''.join([chr(y) for y in result_bytes])
	result = result_bytes if base == 256 else result_string

	return result



def encrypt(public_key, message, mod, a, b, base_point):
	# Changes string to int
	plaintext = textToInt(message)

	plain_coordinates = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], plaintext, a, b, mod)

	print("message is represented as the following point coordinates")
	print("plain coordinates: ", plain_coordinates)

	publicKey = decode_pubkey(public_key)

	randomKey = 28695618543805844332113829720373285210420739438570883203839696518176414791234
	#import random
	#randomKey = random.getrandbits(128)

	c1 = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], randomKey, a, b, mod)
	c2 = EccCore.applyDoubleAndAddMethod(publicKey[0], publicKey[1], randomKey, a, b, mod)
	c2 = EccCore.pointAddition(c2[0], c2[1], plain_coordinates[0], plain_coordinates[1], a, b, mod)		
	
	print("c1: ", c1)
	print("c2: ", c2)
	wrt_list = []
	wrt_list.append(c1)
	wrt_list.append(c2)
	
	with open('nytt_file.txt', 'w') as f:
		for item in wrt_list:
			f.write("%s\n" % item)

	
def decrypt(priv_key, message, mod, order, a, b, base_point):	
	secretKey = decode_privkey(priv_key)
	#secret key times c1
	dx, dy = EccCore.applyDoubleAndAddMethod(c1[0], c1[1], secretKey, a, b, mod)
	#-secret key times c1
	dy = dy * -1 #curve is symmetric about x-axis. in this way, inverse point found

	#c2 + secret key * (-c1)
	decrypted = EccCore.pointAddition(c2[0], c2[1], dx, dy, a, b, mod)
	print("decrypted coordinates: ",decrypted)
		

	new_point = EccCore.pointAddition(base_point[0], base_point[1], base_point[0], base_point[1], a, b, mod) #2P

	#brute force method
	for i in range(3, order):
		new_point = EccCore.pointAddition(new_point[0], new_point[1], base_point[0], base_point[1], a, b, mod)
		if new_point[0] == decrypted[0] and new_point[1] == decrypted[1]:
			
			print("decrypted message as numeric: ",i)
			print("decrypted message: ",intToText(i))
			
			break


def main(argv):
	fun = argv[0]
	key = argv[1]
	mess = argv[2]
	# Initialize the elliptic curve
	mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
	order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
	a = 0
	b = 7
	base_point = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]

	print('herna')
	if fun in ['encrypt', 'e']:
		encrypt(key, mess, mod, a, b, base_point)
	elif fun in ['decrypt', 'd']:
		decrypt(key, mess, mod, order, a, b, base_point)
	else: print('Invalid')

if __name__== "__main__":
	main(sys.argv[1:])