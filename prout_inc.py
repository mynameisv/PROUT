#!/usr/bin/env python3 -OO
# coding: utf8
"""

 * Password incRementer Ordering Unsigned-integer Tool

Take a dictionnary and create variation by 
incrementing all numbers

qwerasdf20! => qwerasdf00!..qwerasdf99!
viki@1604 => viki@1500..viki@1700
20September1980 => 00September1900..99September2200

 * License

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
Version 3, August 2017
Everyone is permitted to copy and distribute verbatim or modified
copies of this license document, and changing it is allowed as long
as the name is changed.
DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
    You just DO WHAT THE FUCK YOU WANT TO.
    As the "THE BEER-WARE LICENSE", if we meet some day, and you
think this stuff is worth it, you can buy me a beer in return.

"""

# Embedded imports
import copy
import datetime
import logging
from operator import itemgetter
import math
import sys
import time
import hashcat_helpers

# External imports
import docopt
#
##
###
###########################################################
# Globals
#############################
g_readfile_buffer_size = 200_000_000
#hard limit to avoid infinite dic
g_max_variants = 600_000_000

#
##
###
###########################################################
# Command line
#############################
# Help string
cmdline_help = """
Usage:
	prout_inc.py --dic=<file>
	prout_inc.py --dic=<file> [--passsep=<char>] [--passpos=<int>] [--output=<file>] [--dec=<int>] [--inc=<int>]
	
Options:
	-h, --help               help
	--dic=<file>             input text file containing passwords to build the masks
	--passsep=<char>         column separator, empty means file contains only password [default: :]
	--passpos=<int>          column containing passwords (first is 1) [default: 1]
	--output=<file>          masks output file [default: incdec_dic.txt]
	--dec=<int>              decrement number from 1 to ... [default: 10]
	--inc=<int>              increment number from 1 to ... [default: 10]
"""

logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.DEBUG)
logging.info(f'Starting {__file__} ...')

cmdline_opts = docopt.docopt(cmdline_help)

if '--dic' in cmdline_opts:
	try:
		g_hfile = open(cmdline_opts['--dic'], mode='rt', newline="\n", errors='ignore')
	except Exception as e:
		print(f' ! Error: {e}')
		print(cmdline_help)
		sys.exit(1)
else:
	print(cmdline_help)
	sys.exit(1)

g_passsep = ''
if '--passsep' in cmdline_opts and cmdline_opts['--passsep']:
	g_passsep = cmdline_opts['--passsep']

g_passpos = 1
if '--passpos' in cmdline_opts and cmdline_opts['--passpos']:
	g_passpos = int(cmdline_opts['--passpos'])

g_dec = 10
if '--dec' in cmdline_opts and cmdline_opts['--dec']:
	g_dec = int(cmdline_opts['--dec'])

g_inc = 10
if '--inc' in cmdline_opts and cmdline_opts['--inc']:
	g_inc = int(cmdline_opts['--inc'])

g_output_file = 'out_incdec_dic.txt'
if '--output' in cmdline_opts and cmdline_opts['--output']:
	g_output_file = cmdline_opts['--output']

#
##
###
###########################################################
# Functions
#############################
def inc_dec_digits(l:list, inc:int=10, dec:int=10, counter:int=0):
	
	l_variants = []
	l_new = copy.deepcopy(l)

	if counter>=len(l):
		#print('  return []')
		return []

	#print(f'l={l}, len={len(l)}, counter={counter}, l[counter]={l[counter]}')

	if l[counter].isdigit():
		digit = int(l_new[counter])
		digit_len = len(l_new[counter])
		digit_ceil = (10**digit_len)-1
		digit_max = min(digit+inc, digit_ceil)
		digit_min = max(digit-dec, 0)
		#print(f'd:{l[counter]}, len:{digit_len}, ceil:{digit_ceil}, max:{digit_max}, min:{digit_min}')
		
		for i in range(digit, digit_max+1):
			digit_new = f'{i:0{digit_len}}'
			#print(f'digit_new:{digit_new}')
			l_new[counter] = str(digit_new)
			l_variants.append(''.join(l_new))
			#print(f'  call inc inc_dec_digits({l_new}, {inc}, {dec}, {counter+1})')
			l_variants.extend(inc_dec_digits(l_new, inc, dec, counter+1))
		
		for i in range(digit_min, digit):
			digit_new = f'{i:0{digit_len}}'
			l_new[counter] = str(digit_new)
			l_variants.append(''.join(l_new))
			#print(f'  call dec inc_dec_digits({l_new}, {inc}, {dec}, {counter+1})')
			l_variants.extend(inc_dec_digits(l_new, inc, dec, counter+1))

		#print('  return l_variants')
		return l_variants
	else:
		#print('  return inc_dec_digits()')
		return inc_dec_digits(l_new, inc, dec, counter+1)


def main():
	global g_readfile_buffer_size, g_max_variants
	global g_hfile, g_passsep, g_passpos, g_output_file
	global g_dec, g_inc

	print(f'\n[*] Starting {datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")}')

	lines_counter = 0
	lines_counter_last = -1

	counter = 0
	still_content = True
	print(f'\n[*] Parsing file...')
	while still_content == True:

		lines = g_hfile.readlines(g_readfile_buffer_size)

		if not lines:
			print(f'   ! EOF {datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")}')
			still_content = False
			continue

		for line in lines:
			line = line.rstrip('\r\n')
			if g_passsep:
				tab = line.split(g_passsep, g_passpos)
				if len(tab)<(g_passpos+1):
					print(f'   /!\\ Stopping, plit error:{line}')
					pass_counters['error']+=1
					continue
				else:
					passwd = tab[g_passpos]
			else:
				passwd = line

			if passwd[0:5]=='$HEX[':
				try:
					passwd_hex = passwd[5:-1]
					bytes = bytearray.fromhex(passwd_hex)
					escaped = bytes.decode('unicode_escape')
					passwd = escaped.encode('utf8').decode()
				except:
					print(f'   ! Ignoring, problem with hex password decoding:{passwd_hex}')
					pass_counters['error']+=1
					continue

			# Build a list of string and int by parsing char by char
			# regexp could do the job... could do...
			chars = list(passwd)
			found_digit = False
			parts_pos = 0
			parts_last_digit = False
			parts_list = []
			tmp = ''
			for c in chars:
				if c.isdigit():
					found_digit = True
					if parts_last_digit==False:
						# new one
						parts_last_digit = True
						# append the last one, if not empty
						if tmp:
							parts_list.append(tmp)
						tmp = ''
					tmp = f'{tmp}{c}'
				else:
					if parts_last_digit==True:
						# new one
						parts_last_digit = False
						# append the last one, if not empty
						if tmp:
							parts_list.append(tmp)
						tmp = ''
					tmp = f'{tmp}{c}'
			# keep the last tmp
			if tmp:
				parts_list.append(tmp)

			# Increment and decrement each int
			m = ''
			if found_digit:
				m = f'  - Contains digits:{passwd:>24}'
				
				#check if the inc/dec will exceed the hard limit
				exp_count = 1
				incdec = g_dec+g_inc
				for part in parts_list:
					if part.isdigit():
						part_i = int(part)
						if part_i>incdec:
							exp_count = exp_count*incdec
						else:
							exp_count = exp_count*(10**min(len(part), len(str(incdec))))
				
				if exp_count > g_max_variants:
					m = f'{m}, too much digits: {exp_count:>10} potential variations > {g_max_variants} hard limit).'
					print(m)
				else:
					pass_list = inc_dec_digits(parts_list, g_dec, g_inc, 0)
					#print(f'   + build {len(pass_list):>12} passwords')
					m = f'{m}, generated {len(pass_list):>12} passwords'
					print(m)
					with open(g_output_file, 'a')as h:
						h.write("\n".join(pass_list))
						h.write("\n")
						h.close()

#
##
###
###########################################################
# Main
#############################
if __name__ == '__main__':
	main()



