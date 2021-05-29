Password Rulebased Output Unveiler Tool
--------
Generate masks for hashcat mask attack, based on passwords from a dictionnary

Usage:
````
	prout_mask.py --dic=<file>
	prout_mask.py --dic=<file> [--passsep=<char>] [--passpos=<int>] [--output=<file>] [--maxcracking=<seconds>] [--maskminlen=<int>] [--crackspeed=<int>] [--sort=<char>]
````

Options:
````
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
````


Password incRementer Ordering Unsigned-integer Tool
--------
Take a dictionnary and create variation by incrementing all numbers

Usage:
````
	prout_inc.py --dic=<file>
	prout_inc.py --dic=<file> [--passsep=<char>] [--passpos=<int>] [--output=<file>] [--dec=<int>] [--inc=<int>]
````

Options:
````
	-h, --help               help
	--dic=<file>             input text file containing passwords to build the masks
	--passsep=<char>         column separator, empty means file contains only password [default: :]
	--passpos=<int>          column containing passwords (first is 1) [default: 1]
	--output=<file>          masks output file [default: incdec_dic.txt]
	--dec=<int>              decrement number from 1 to ... [default: 10]
	--inc=<int>              increment number from 1 to ... [default: 10]
````