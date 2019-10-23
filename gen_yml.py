#!/usr/bin/env python

import sys
import argparse

try:
	from apikey import APIKEY
except:
	APIKEY = None

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Generate a security release .yml')
	parser.add_argument('--verbose', '-v', action='store_true', help='Print out debugging info')
	parser.add_argument('version', help='Version to generate queries for')
	args = parser.parse_args(sys.argv[1:])
	if not APIKEY:
		print "API Key not defined in apikey.py"
		print "Fill that in with an API Key able to access security bugs."
		sys.exit(1)
