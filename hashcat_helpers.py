#!/usr/bin/env python3 -OO
# coding: utf8

# hashcat_helper

# Allowed class/function to be imported
__all__ = [
	'get_pass_from_hashcat_hex',
	'get_pass_mask',
	'get_pass_complexity'
]


def get_pass_from_hashcat_hex(passwd:str) -> str:
	"""
	Decode hashcat hex format password $HEX[...]
	
	:param passwd: the password
	:type passwd: str

	:return: hex decode password or the password if it wasn't encoded
	"""
	if passwd[0:5]=='$HEX[' or passwd[0:5]=='$hex[':
		try:
			passwd_hex = passwd[5:-1]
			bytes = bytearray.fromhex(passwd_hex)
			escaped = bytes.decode('unicode_escape')
			passwd = escaped.encode('utf8').decode()
		except:
			# problem with hex password decoding
			return ''
	else:
		return passwd



def get_pass_mask(passwd:str, limit:int=0 ) -> str:
	"""
	Build the hascat mask from a password
	
	:param passwd: the password
	:type passwd: str
	:param limit: the password length limit to limit, 0 means no limit
	:type limit: int
	
	:return: hashcat mask as str
	"""
	# Specials
	specials = list(' !"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~')

	# Decode potential hex pass
	passwd = get_pass_from_hashcat_hex(passwd)
	mask = ''
	count=0
	# Build mask
	for c in list(passwd):
		o = ord(c)
		if o>=97 and o<=122: #	c.islower():
			mask = f'{mask}?l'
		elif o>=65 and o<=90: #elif c.isupper():
			mask = f'{mask}?u'
		elif  c.isdigit():
			mask = f'{mask}?d'
		elif c in specials:
			mask = f'{mask}?s'
		elif c==0:
			pass
		else:
			mask = f'{mask}?b'
		
		if limit!=0:
			count+= 1
			if count>=limit:
				break
	return mask


	
def get_pass_complexity(passwd:str) -> int:
	"""
	Calculate the cracking complexity of a password and
	
	:param passwd: the password
	:type passwd: str
	
	:return: complexity as int
	"""
	# Specials
	specials = list(' !"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~')

	# Decode potential hex pass
	passwd = get_pass_from_hashcat_hex(passwd)
	complexity = 1
	
	# Build mask
	for c in list(passwd):
		o = ord(c)
		if o>=97 and o<=122: #	c.islower():
			complexity = complexity * 26
		elif o>=65 and o<=90: #elif c.isupper():
			complexity = complexity * 26
		elif c.isdigit():
			complexity = complexity * 10
		elif c in specials:
			complexity = complexity * len(specials)
		elif c==0:
			pass
		else:
			complexity = complexity * 256
	return complexity
