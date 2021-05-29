#!/usr/bin/env python3 -OO
# coding: utf8
"""

 * Password Rulebased Output Unveiler Tool
Generate masks for hashcat mask attack, based on passwords from a dictionnary

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
g_sort_items = {
	'd': {'item': 'duration', 'reverse': False },
	'D': {'item': 'duration', 'reverse': True },
	'c': {'item': 'count', 'reverse': False },
	'C': {'item': 'count', 'reverse': True },
}
#
##
###
###########################################################
# Command line
#############################
# Help string
cmdline_help = """
Usage:
	prout_mask.py --dic=<file>
	prout_mask.py --dic=<file> [--passsep=<char>] [--passpos=<int>] [--output=<file>] [--maxcracking=<seconds>] [--maskminlen=<int>] [--crackspeed=<int>] [--sort=<char>]
	
Options:
	-h, --help               help
	--dic=<file>             input text file containing passwords to build the masks
	--passsep=<char>         column separator, empty means file contains only password [default: :]
	--passpos=<int>          column containing passwords (first is 1) [default: 1]
	--output=<file>          masks output file [default: masks.txt]
	--maxcracking=<seconds>  max cracking duration in seconds to exclude too long masks [default: 86400]
	--maskminlen=<int>       min len of a mask, exclude smaller mask
	--crackspeed=<int>       your hardware cracking speed for the hash you wanna crack [default: 5_000_000_000]
	--sort=<char>            sort masks output  by :
                                 'd' : duration in ascending order [default: d]
                                 'D' : duration in decreasing order
                                 'c' : count/occurence in ascending order
                                 'C' : count/occurence in decreasing order
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

g_output_file = 'masks.txt'
if '--output' in cmdline_opts and cmdline_opts['--output']:
	g_output_file = cmdline_opts['--output']

g_maxcracking = 24*60*60
if '--maxcracking' in cmdline_opts and cmdline_opts['--maxcracking']:
	g_maxcracking = int(cmdline_opts['--maxcracking'])

# Cracking speed for ntlm on my 4xRTX 2080 = 80 000 MH/s
g_crackspeed = 80_000_000_000
if '--crackspeed' in cmdline_opts and cmdline_opts['--crackspeed']:
	g_crackspeed = int(cmdline_opts['--crackspeed'])

# Do not get masks with len < this value (x2 because there is 2 char : ?l ?u...)
g_maskminlen = 9*2
if '--maskminlen' in cmdline_opts and cmdline_opts['--maskminlen']:
	g_maskminlen = int(cmdline_opts['--maskminlen'])

# Do not get masks with len < this value (x2 because there is 2 char : ?l ?u...)
g_sort = 'd'
if '--sort' in cmdline_opts and cmdline_opts['--sort']:
	g_sort = cmdline_opts['--sort']
	if g_sort not in g_sort_items:
		print(cmdline_help)
		sys.exit(1)
#
##
###
###########################################################
# Function
#############################
def main():
	global g_readfile_buffer_size
	global g_hfile, g_passsep, g_passpos, g_output_file
	global g_maxcracking, g_crackspeed, g_maskminlen, g_sort, g_sort_items


	# build masks dictionnary
	"""
	masks = {
		'here a mask like ?d?d?u....' : {
			'mask': the mask, again, as a string
			'count': number of occurence of the mask, as an int
			'complexity': the complexity as the number of possibilities regarding the mask, as an int
			'duration': duration to crack the pass , as an int
		}
	}
	"""
	print(f'\n[*] Starting {datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")}')

	masks = {}
	pass_counters = {'ok':0, 'error':0, 'to short':0}
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
				
			mask = hashcat_helpers.get_pass_mask(passwd)
			complexity = hashcat_helpers.get_pass_complexity(passwd)
			
			if len(mask)>=g_maskminlen:
				pass_counters['ok']+=1
				if mask in masks:
					masks[mask]['count']+= 1
				else:
					masks[mask] = {
						'mask': mask,
						'count':1,
						'complexity': complexity,
						'duration':math.floor(complexity / g_crackspeed)
					}
			else:
				pass_counters['to short']+=1

		counter+=1
		
		if counter%10000==0:
			print(f'   * pass ok:{pass_counters["ok"]:>12,} short:{pass_counters["to short"]:>12,} error:{pass_counters["error"]:>12,}')
	
	masks_len = len(masks)
	print(f'   > Found {masks_len:>6} uniq masks for {pass_counters["ok"]:,} pass, {pass_counters["to short"]:,} ignored to short, {pass_counters["error"]:>,} ignored error')

	# remove too long cracking
	for key in list(masks.keys()):
		if masks[key]['duration'] > g_maxcracking:
			del masks[key]

	"""
	for mask in masks:
		if masks[mask]['duration'] < g_maxcracking:
			new_masks[mask] = masks[mask]
	"""
	nd = round(g_maxcracking/86400,2)
	print(f'\n[*] Removing too long cracking, more than {nd:6,} days aka {g_maxcracking:>12,}...')
	new_masks = {}
	for mask in masks:
		if masks[mask]['duration'] < g_maxcracking:
			new_masks[mask] = masks[mask]
	print(f'   > Left  {len(new_masks):>6} masks crackable in a reasonable time, less than {nd:6,} days aka {g_maxcracking:>12,} seconds.')

	# keep only most present
	"""
	top_count = 1_000_000
	print('')
	print(f' > Keep only top {top_count} most present')
	new_masks = {}
	if len(masks_ordered_by_count) < top_count:
		pass
	else:
		for i in range(len(masks_ordered_by_count)-top_count, len(masks_ordered_by_count)):
			mask = masks_ordered_by_count[i]['mask']
			new_masks[mask] = copy.deepcopy(masks_ordered_by_count[i])
	print(f' > found {len(new_masks):>6} masks')
	"""

	# sort
	print(f'\n[*] Sorting...')
	masks_ordered = sorted(
		new_masks.values(),
		key=itemgetter(g_sort_items[g_sort]['item']),
		reverse=g_sort_items[g_sort]['reverse']
	)

	# generate masks
	print(f'\n[*] Writing masks and comments...')

	output_string = ''
	for key in range(0, len(masks_ordered)):
		duration_str = str(datetime.timedelta(seconds=masks_ordered[key]['duration']))
		output_string+= f'# {masks_ordered[key]["mask"]:<36} x {masks_ordered[key]["count"]:>9,}, duration:{duration_str:>24}\n'
		output_string+= f'{masks_ordered[key]["mask"]}\n'


	print(f'\n[*] Write masks to {g_output_file}')
	with open(g_output_file, 'w')as h:
		h.write(output_string)
		h.close()

	print('')
	print(f'\n \o/ All done.')
#
##
###
###########################################################
# Main
#############################
if __name__ == '__main__':
	main()
