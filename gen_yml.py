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

from gen_queries import versionToESRs, rollupListMainAndESR, rollupListMainOnly, rollupListESROnly

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def cleanUpRealName(name):
	name = re.sub(" \[:[^\]]+\]", "", name)
	name = re.sub(" \(:[^\)]+\)", "", name)
	name = re.sub(" \(needinfo[^\)]+\)", "", name)
 	name = re.sub(" \(ni [^\)]+\)", "", name)
	return name

def getSeverity(bugJSON):
	severity = None
	for k in bugJSON['keywords']:
		if k in ["sec-critical", "sec-high", "sec-moderate", "sec-low"]:
			thisSev = k.replace("sec-", "")
			if severity is not None:
				severity = getMaxSeverity(severity, thisSev)
			else:
				severity = thisSev
	if severity is None:
		raise Exception(str(bugJSON['id']) + " is missing a sec keyword")
	return severity

class Advisory:
	def __init__(self, bugJSON, advisoryText):
		self.id = bugJSON['id']
		self.severity = getSeverity(bugJSON)
		advisory_lines = advisoryText.split("\n")
		self.cve = bugJSON['alias'] if bugJSON['alias'] else ""
		self.title = advisory_lines[0].strip()
		self.reporter = advisory_lines[1].strip() #cleanUpRealName(bugJSON['creator_details']['real_name'])
		self.description = "\n".join(advisory_lines[2:]).strip()
	def pprint(self):
		print(self.id)
		print("\t", self.severity)
		print("\t", self.title)
		print("\t", self.reporter)
		print("\t", self.description)
		print("\t")
	def getCVE(self):
		if self.cve:
			return self.cve
		return "CVE-FIXME-YYY"
	def getTitle(self):
		if ":" in self.title:
			return "'" + self.title + "'"
		return self.title

def sortAdvisories(advisories):
	for a in advisories:
		if a.severity == "critical":
			yield a
	for a in advisories:
		if a.severity == "high":
			yield a
	for a in advisories:
		if a.severity == "moderate":
			yield a
	for a in advisories:
		if a.severity == "low":
			yield a

def doBugRequest(link):
	r = requests.get(link)
	bugs = r.json()
	return bugs['bugs']

def getBugs(esr, version):
	nonRollUpLink = "https://bugzilla.mozilla.org/rest/bug?api_key=" + APIKEY + \
	"&f1=OP" + \
	"&f2=status_whiteboard&o2=substring&v2=adv-" + ("esr" if esr else "main") + version + "%2B" \
	"&f3=status_whiteboard&o3=notsubstring&v3=adv-" + ("esr" if esr else "main") + version + "%2Br" + \
	"&f4=CP"
	return doBugRequest(nonRollUpLink)

def getAdvisoryAttachment(bugid):
	link = "https://bugzilla.mozilla.org/rest/bug/" + str(bugid) + "/attachment?api_key=" + APIKEY
	r = requests.get(link)
	attachments = r.json()['bugs'][str(bugid)]
	advisory = None
	for a in attachments:
		if a['description'] == "advisory.txt" and not a['is_obsolete']:
			if advisory is not None:
				raise Exception(str(bugid) + " has two advisory.txt attachments")
			advisory = base64.b64decode(a['data'])
	if advisory is None:
		raise Exception(str(bugid) + " is missing an advisory.txt attachment")
	return advisory

def getMaxSeverity(current, this):
	if this == "critical":
		return "critical"
	elif current in ["low", "moderate"] and this == "high":
		return "high"
	elif current in ["low"] and this == "moderate":
		return "moderate"
	return current

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Generate a security release .yml')
	parser.add_argument('--verbose', '-v', action='store_true', help='print(out debugging info')
	parser.add_argument('--esr', action='store_true', help='Generate the ESR document for the given full version')
	parser.add_argument('version', help='Version to generate queries for. Do not give an ESR version; give the normal version and specify --esr')
	args = parser.parse_args(sys.argv[1:])
	if not APIKEY:
		eprint("API Key not defined in apikey.py")
		eprint("Fill that in with an API Key able to access security bugs.")
		sys.exit(1)
	if float(args.version) != int(float(args.version)) and not args.esr:
		eprint("This is a dot-release. If this is an ESR release, be sure to put the full version and --esr")

	mainVersion = args.version
	esrVersion = versionToESRs(float(args.version))
	if len(esrVersion) != 1:
		raise Exception("This script isn't set up to handle two ESR versions in flight at once. Development needed.")
	esrVersion = str(esrVersion[0])
	targetVersion = esrVersion if args.esr else mainVersion
	eprint("Generating advisories for Version", targetVersion, ("(which is an ESR release)" if args.esr else ""))

	# Non-rollup bugs
	bugs = getBugs(args.esr, targetVersion)
	advisories = []
	for b in bugs:
		if b['id'] in [1441468, 1587976]:
			continue
		advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))

	maxSeverity = "low"
	for a in advisories:
		maxSeverity = getMaxSeverity(maxSeverity, a.severity)

	print("## mfsa" + str(datetime.date.today().year) + "-FIXME.yml")
	print("announced: FIXME")
	print("impact:", maxSeverity)
	print("fixed_in:")
	print("- Firefox " + ("ESR" if args.esr else "") + targetVersion)
	print("title: Security Vulnerabilities fixed in Firefox " + ("ESR" if args.esr else "") + targetVersion)
	print("description: |")
	print("  Do you want a description?")

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

	def doRollups(buglist, versionTitle, priorVersionTitle):
		if len(buglist) == 0:
			return

		rollupIDs = []
		rollupReporters = set()
		rollupMaxSeverity = "low"
		for b in buglist:
			rollupIDs.append(b['id'])
			name = cleanUpRealName(b['creator_detail']['real_name'])
			if name not in ["Treeherder Bug Filer"]:
				rollupReporters.add(name)
			try:
				rollupMaxSeverity = getMaxSeverity(rollupMaxSeverity, getSeverity(b))
			except:
				pass

		rollupEnd = "reported memory safety bugs present in " + priorVersionTitle + ". Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code."
		print("  CVE-XXX-rollup:")
		print("    title: Memory safety bugs fixed in", versionTitle)
		print("    impact:", rollupMaxSeverity)
		print("    reporter: Mozilla developers and community")
		print("    description: |")
		print("      Mozilla developers and community members", ", ".join(rollupReporters), rollupEnd)
		print("    bugs:")
		print("      - url:", ", ".join([str(i) for i in rollupIDs]))
		print("        desc: Memory safety bugs fixed in", versionTitle)

	# Rollup Bug for Main + ESR. Always do this one.
	url = rollupListMainAndESR(mainVersion, esrVersion) + "&api_key=" + APIKEY
	doRollups(doBugRequest(url),
		"Firefox " + mainVersion + " and Firefox ESR " + esrVersion,
		"Firefox " + str(int(mainVersion)-1) + " and Firefox ESR " + str(float(esrVersion)-.1))
	if not args.esr:
	# Rollup Bug for Main Only 
		url = rollupListMainOnly(mainVersion, esrVersion) + "&api_key=" + APIKEY
		doRollups(doBugRequest(url), 
			"Firefox " + mainVersion,
			"Firefox " + str(int(mainVersion)-1))
	else:
	# Rollup bug for ESR only
		url = rollupListESROnly(mainVersion, esrVersion) + "&api_key=" + APIKEY
		doRollups(doBugRequest(url),
			"Firefox ESR " + esrVersion,
			"Firefox ESR " + str(float(esrVersion) - .1))