import time
import EccCore
import binascii
import hashlib
import re
import base64
import time
import random
import hmac

#------------------------------------

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

def get_code_string(base):
	if base in code_strings:
		return code_strings[base]
	else:
		raise ValueError("Invalid base!")

#------------------------------------
#curve configuration

mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

#curve configuration
# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
a = 0
b = 7

#base point on the curve
base_point = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]

print("---------------------")
print("initial configuration")
print("---------------------")
print("Curve: y^2 = x^3 + ",a,"*x + ",b, " mod ", mod," , #F(",mod,") = ", order)
print("Base point: (",base_point[0],", ",base_point[1],")")
#print("modulo: ", mod)
#print("order of group: ", order)
print()
#------------------------------------
#symmetric encryption

encryption_begins = time.time()

print("--------------------------------------------------------------")
print("public key generation")

message = 'hi'
plaintext = textToInt(message)
print("message: ",message,". it is numeric matching is ",plaintext)

plain_coordinates = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], plaintext, a, b, mod)

print("message is represented as the following point coordinates")
print("plain coordinates: ",plain_coordinates)

pub = '043e6fbace2ef2ebff56166806ff1d4568ec356edbc0bf97e6fe675f179a017a5af6b0cf80c897ae09a8117392cf8d0f930d494af5b57e2f81518adeeaf6431e1a'

secretKey = 75263518707598184987916378021939673586055614731957507592904438851787542395619

publicKey = decode_pubkey(pub)

print("\npublic key: ",publicKey)

print("--------------------------------------------------------------")
print("encryption")

randomKey = 28695618543805844332113829720373285210420739438570883203839696518176414791234
#import random
#randomKey = random.getrandbits(128)

c1 = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], randomKey, a, b, mod)

c2 = EccCore.applyDoubleAndAddMethod(publicKey[0], publicKey[1], randomKey, a, b, mod)
c2 = EccCore.pointAddition(c2[0], c2[1], plain_coordinates[0], plain_coordinates[1], a, b, mod)

print("\nciphertext")
print("c1: ", c1)
print("c2: ", c2)

encryption_ends = time.time()

print("encryption lasts ",encryption_ends-encryption_begins," seconds")
print("--------------------------------------------------------------")
#plaintext = c2 - secretKey * c1

decryption_begins = time.time()

#secret key times c1
dx, dy = EccCore.applyDoubleAndAddMethod(c1[0], c1[1], secretKey, a, b, mod)
#-secret key times c1
dy = dy * -1 #curve is symmetric about x-axis. in this way, inverse point found

#c2 + secret key * (-c1)
decrypted = EccCore.pointAddition(c2[0], c2[1], dx, dy, a, b, mod)
print("decrypted coordinates: ",decrypted)
	
#-----------------------------------

decrytion_begin = time.time()
new_point = EccCore.pointAddition(base_point[0], base_point[1], base_point[0], base_point[1], a, b, mod) #2P

#brute force method
for i in range(3, order):
	new_point = EccCore.pointAddition(new_point[0], new_point[1], base_point[0], base_point[1], a, b, mod)
	if new_point[0] == decrypted[0] and new_point[1] == decrypted[1]:
		
		print("decrypted message as numeric: ",i)
		print("decrypted message: ",intToText(i))
		
		break

decrytion_end = time.time()
print("decryption lasts ",decrytion_end-decrytion_begin," seconds")

def encrypt(public_key, message):
	# Initialize the elliptic curve
	mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
	order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

	#curve configuration
	# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
	a = 0
	b = 7

	#base point on the curve
	base_point = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]

	# Convert the public_key to coords on x and y


	# Message reperesened as coordinates

	plaintext = textToInt(message)
	plain_coordinates = EccCore.applyDoubleAndAddMethod(base_point[0], base_point[1], plaintext, a, b, mod)

