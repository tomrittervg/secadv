#!/usr/bin/env python

import sys
import base64
import datetime
import requests
import argparse

try:
	from apikey import APIKEY
except:
	APIKEY = None

class Advisory:
	def __init__(self, bugJSON, advisoryText):
		self.id = bugJSON['id']
		self.severity = None
		for k in bugJSON['keywords']:
			if k in ["sec-critical", "sec-high", "sec-moderate", "sec-low"]:
				if self.severity is not None:
					raise Exception(str(bugJSON['id']) + " has two sec keywords set")
				self.severity = k.replace("sec-", "")
		if self.severity is None:
			raise Exception(str(bugJSON['id']) + " is missing a sec keyword")
		advisory_lines = advisoryText.split("\n")
		self.cve = bugJSON['alias'] if bugJSON['alias'] else ""
		self.title = "This is the title" #advisory_lines[0]
		self.reporter = "Bob Dole"
		self.description = "\n".join(advisory_lines[1:]).strip() or "Here is a description"
	def pprint(self):
		print self.id
		print "\t", self.severity
		print "\t", self.title
		print "\t", self.reporter
		print "\t", self.description
		print "\t"
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

def getBugs(version):
	nonRollUpLink = "https://bugzilla.mozilla.org/rest/bug?api_key=" + APIKEY + \
	"&f1=OP" + \
	"&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B" \
	"&f3=status_whiteboard&o3=notsubstring&v3=adv-main" + version + "%2Br" + \
	"&f4=CP"
	r = requests.get(nonRollUpLink)
	bugs = r.json()
	return bugs['bugs']

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

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Generate a security release .yml')
	parser.add_argument('--verbose', '-v', action='store_true', help='Print out debugging info')
	parser.add_argument('version', help='Version to generate queries for')
	args = parser.parse_args(sys.argv[1:])
	if not APIKEY:
		print "API Key not defined in apikey.py"
		print "Fill that in with an API Key able to access security bugs."
		sys.exit(1)

	bugs = getBugs(args.version)
	advisories = []
	for b in bugs:
		if b['id'] in [1441468, 1587976]:
			continue
		advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))

	maxSeverity = "low"
	for a in advisories:
		if a.severity == "critical":
			maxSeverity = "critical"
			break
		elif maxSeverity in ["low", "moderate"] and a.severity == "high":
			maxSeverity = "high"
		elif maxSeverity in ["low"] and a.severity == "moderate":
			maxSeverity = "moderate"


	print "## mfsa" + str(datetime.date.today().year) + "-FIXME.yml"
	print "announced: FIXME"
	print "impact:", maxSeverity
	print "fixed_in:"
	print "- Firefox", args.version
	print "title: Security Vulnerabilities fixed in - Firefox", args.version
	print "advisories:"
	for a in sortAdvisories(advisories):
		print "  " + a.getCVE() + ":"
		print "    title:", a.getTitle()
		print "    impact:", a.severity
		print "    reporter:", a.reporter
		print "    description: |"
		print "      " + a.description
		print "    bugs:"
		print "      - url:", a.id