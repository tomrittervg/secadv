#!/usr/bin/env python3

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

from gen_queries import versionToESRs, nonRollupList, rollupListMainAndESR, rollupListMainOnly, rollupListESROnly
from yml_utils import *

def getBugs(targetVersion, mainVersion, esr):
    url = nonRollupList(targetVersion, mainVersion, esr).replace("buglist.cgi", "rest/bug") + "&api_key=" + APIKEY
    return doBugRequest(url)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a security release .yml')
    parser.add_argument('--verbose', '-v', action='store_true', help='print(out debugging info')
    parser.add_argument('--esr', action='count', default=0, help='Generate the ESR document for the given full version. Specify twice to generate for the second ESR version of a release.')
    parser.add_argument('--exclude', action='append', help='Bug IDs to exclude from checks about attachments')
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
    if len(esrVersion) > 1:
        if args.esr <= len(esrVersion):
            esrVersion = str(esrVersion[args.esr - 1])
        else:
            eprint("--esr was specified more times than we have ESR versions to generate")
    else:
        esrVersion = esrVersion[0]
    targetVersion = esrVersion if args.esr else mainVersion
    eprint("Generating advisories for Version", targetVersion, ("(which is an ESR release)" if args.esr else ""))

    # Figure out the rollup situation
    url = rollupListMainAndESR(mainVersion, esrVersion) + "&api_key=" + APIKEY
    shared_rollups = doBugRequest(url)
    if not args.esr:
        url = rollupListMainOnly(mainVersion, esrVersion) + "&api_key=" + APIKEY
    else:
        url = rollupListESROnly(mainVersion, esrVersion) + "&api_key=" + APIKEY
    version_specific_rollups = doBugRequest(url)

    # Non-rollup bugs
    bugs = getBugs(targetVersion, mainVersion, args.esr)
    advisories = []
    for b in bugs:
        if b['id'] in [1441468, 1587976] or (args.exclude is not None and str(b['id']) in args.exclude):
            continue
        advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))

    if len(shared_rollups) == 1:
        b = shared_rollups[0]
        if (args.exclude is None or str(b['id']) not in args.exclude):
            try:
                advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))
            except:
                raise Exception("Could not find an advisory for %s which is the only bug in the shared rollup." % b['id'])
            shared_rollups = []
    if len(version_specific_rollups) == 1:
        b = version_specific_rollups[0]
        if (args.exclude is None or str(b['id']) not in args.exclude):
            try:
                advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))
            except:
                raise Exception("Could not find an advisory for %s which is the only bug in the version-specific rollup." % b['id'])
            version_specific_rollups = []

    maxSeverity = "low"
    for a in advisories:
        maxSeverity = getMaxSeverity(maxSeverity, a.severity)

    thisyear = str(datetime.date.today().year)
    print("## mfsa" + thisyear + "-FIXME.yml")
    print("announced: FIXME <Month> <Day of Month>, <Year>")
    print("impact:", maxSeverity)
    print("fixed_in:")
    print("- Firefox " + ("ESR " if args.esr else "") + targetVersion)
    print("title: Security Vulnerabilities fixed in Firefox " + ("ESR " if args.esr else "") + targetVersion)
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

        if len(buglist) == 1:
            raise Exception("We shouldn't be here for a single bug.")

        rollupIDs = []
        rollupReporters = set()
        rollupMaxSeverity = "low"
        for b in buglist:
            rollupIDs.append(b['id'])
            name = cleanUpRealName(b['creator_detail']['real_name'])
            if name in ["Christian Holler", "Jason Kratzer", "Tyson Smith", "Jesse Schwartzentruber"]:
                rollupReporters.add("the Mozilla Fuzzing Team")
            elif name not in ["Treeherder Bug Filer"]:
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
    doRollups(shared_rollups,
        "Firefox " + mainVersion + " and Firefox ESR " + esrVersion,
        "Firefox " + str(int(mainVersion)-1) + " and Firefox ESR " + str(float(esrVersion)-.1))
    if not args.esr:
    # Rollup Bug for Main Only 
        doRollups(version_specific_rollups,
            "Firefox " + mainVersion,
            "Firefox " + str(int(mainVersion)-1))
    else:
    # Rollup bug for ESR only
        doRollups(doBugRequest(url),
            "Firefox ESR " + esrVersion,
            "Firefox ESR " + str(float(esrVersion) - .1))