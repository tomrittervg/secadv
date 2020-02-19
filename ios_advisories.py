#!/usr/bin/env python

from __future__ import print_function

import re
import sys
import base64
import datetime
import requests
import argparse

try:
	from apikey import APIKEY
except:
	APIKEY = None

from yml_utils import *

def getBugs(version):
	link = "https://bugzilla.mozilla.org/rest/bug?api_key=" + APIKEY + \
	"&f1=OP" + \
	"&f2=cf_tracking_fxios&o2=equals&v2=" + version + \
	"&f3=CP"
	return doBugRequest(link)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Generate a security release .yml')
	parser.add_argument('--verbose', '-v', action='store_true', help='print(out debugging info')
	parser.add_argument('version', help='Version to generate queries for.')
	args = parser.parse_args(sys.argv[1:])
	if not APIKEY:
		eprint("API Key not defined in apikey.py")
		eprint("Fill that in with an API Key able to access security bugs.")
		sys.exit(1)

	version = str(args.version)

	eprint("Generating advisories for Firefox for iOS Version", version)

	# Non-rollup bugs
	bugs = getBugs(version)
	if not len(bugs):
		eprint("No bugs found in Bugzilla for version", version, "- have a nice day!")
		sys.exit(0)
	if not sanityCheckBugs(bugs, require_cves=True):
		eprint("It looks like there are oddities related to the bugs for version", version, ". You will need to resolve these to continue.")
		sys.exit(1)

	advisories = []
	for b in bugs:
		advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))

	maxSeverity = "low"
	for a in advisories:
		maxSeverity = getMaxSeverity(maxSeverity, a.severity)

	print("## mfsa" + str(datetime.date.today().year) + "-FIXME.yml")
	print("announced: FIXME <Month> <Day of Month>, <Year>")
	print("impact:", maxSeverity)
	print("fixed_in:")
	print("- Firefox for iOS " + version)
	print("title: Security Vulnerabilities fixed in Firefox for iOS " + version)

	print("advisories:")
	for a in sortAdvisories(advisories):
		print("  " + a.getCVE() + ":")
		print("    title:", a.getTitle())
		print("    impact:", a.severity)
		print("    reporter:", a.reporter)
		print("    description: |")
		print("      " + a.description)
		print("    bugs:")
		print("      - url:", a.id)
