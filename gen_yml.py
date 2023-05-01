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

from gen_queries import versionToESRs, nonRollupList, rollupListMainAndESR, rollupListMainOnly, rollupListMain, rollupListESROnly, rollupListESR
from yml_utils import *

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
    allEsrVersions = versionToESRs(float(args.version))
    if len(allEsrVersions) > 1:
        if args.esr <= len(allEsrVersions):
            esrVersion = str(allEsrVersions[args.esr - 1])
        else:
            eprint("--esr was specified more times than we have ESR versions to generate")
    else:
        esrVersion = allEsrVersions[0]
    targetVersion = esrVersion if args.esr else mainVersion
    eprint("Generating advisories for Version", targetVersion, ("(which is an ESR release)" if args.esr else ""))

    # -------------------------------------------------------------
    # Figure out the rollup situation
    # This is easy if there is only one ESR version and hard if there are two.
    # With one ESR, bugs will either be non-rollup, rollup-to-main, rollup-to-esr, or rollup-to-main-and-esr
    # With two ESRs, bugs could be non-rollup, rollup-to-main, rollup-to-esr1, rollup-to-esr2, rollup-to-main-and-esr1, rollup-to-main-and-esr2, rollup-to-esr1-and-esr2, or rollup-to-main-and-esr1-and-esr2
    # We're giong to try and detect this behavior but only warn the user about it.

    nonRollUpBugs = []
    sharedRollupBugs = []
    rollUpBugs = []

    url = rollupListMainAndESR(mainVersion, esrVersion) + "&api_key=" + APIKEY
    sharedRollupBugs = doBugRequest(url)
    if not args.esr:
        url = rollupListMainOnly(mainVersion, allEsrVersions) + "&api_key=" + APIKEY
    else:
        url = rollupListESROnly(mainVersion, esrVersion) + "&api_key=" + APIKEY
    version_specific_rollups = doBugRequest(url)

    # Non-rollup bugs
    url = nonRollupList(targetVersion, mainVersion, args.esr).replace("buglist.cgi", "rest/bug") + "&api_key=" + APIKEY
    nonRollUpBugs = doBugRequest(url)

    if len(allEsrVersions) > 1:
        assert(len(allEsrVersions) == 2)

        non_rollup = set([b['id'] for b in doBugRequest(nonRollupList(targetVersion, mainVersion, args.esr).replace("buglist.cgi", "rest/bug") + "&api_key=" + APIKEY)])
        rollup_to_main = set([b['id'] for b in doBugRequest(rollupListMain(mainVersion) + "&api_key=" + APIKEY)])
        rollup_to_esr1 = set([b['id'] for b in doBugRequest(rollupListESR(allEsrVersions[0]) + "&api_key=" + APIKEY)])
        rollup_to_esr2 = set([b['id'] for b in doBugRequest(rollupListESR(allEsrVersions[1]) + "&api_key=" + APIKEY)])
        rollup_to_main_and_esr1 = rollup_to_main.intersection(rollup_to_esr1)
        rollup_to_main_and_esr2 = rollup_to_main.intersection(rollup_to_esr2)
        rollup_to_esr1_and_esr2 = rollup_to_esr1.intersection(rollup_to_esr2)
        rollup_to_main_and_esr1_and_esr2 = rollup_to_main.intersection(rollup_to_esr1).intersection(rollup_to_esr2)

        eprint("OKAY, so you've got two ESR versions, the rollups are going to be complicated.")
        eprint("I'm _not_ going to correctly write the rollup advisories, but I will try to make it easier for you by telling you the bug numbers.")
        eprint("If any of these lists is a single bug, you're probably going to need to write an advisory for it, and manually insert it into the correct yaml file")

        # rollup-to-main-and-esr1-and-esr2
        if rollup_to_main_and_esr1_and_esr2:
            eprint("Bugs that are in all three %s, %s, and %s: %s" % (mainVersion, allEsrVersions[0], allEsrVersions[1], rollup_to_main_and_esr1_and_esr2))
        
        # rollup-to-esr1-and-esr2
        if rollup_to_esr1_and_esr2 - rollup_to_main:
            eprint("Bugs that are in only the ESRs %s and %s: %s" % (allEsrVersions[0], allEsrVersions[1], rollup_to_esr1_and_esr2 - rollup_to_main))

        # rollup-to-main-and-esr1
        if rollup_to_main_and_esr1 - rollup_to_esr2:
            eprint("Bugs that are only in %s and %s: %s" % (mainVersion, allEsrVersions[0], rollup_to_main_and_esr1 - rollup_to_esr2))
        # rollup-to-main-and-esr2
        if rollup_to_main_and_esr2 - rollup_to_esr1:
            eprint("Bugs that are only in %s and %s: %s" % (mainVersion, allEsrVersions[1], rollup_to_main_and_esr2 - rollup_to_esr1))

        # rollup-to-main
        if rollup_to_main - rollup_to_esr1 - rollup_to_esr2:
            eprint("Bugs that are only in %s and not in either ESR: %s" % (mainVersion, rollup_to_main - rollup_to_esr1 - rollup_to_esr2))

        # rollup-to-esr2
        if rollup_to_esr2 - rollup_to_esr1 - rollup_to_main:
            eprint("Bugs that are only in %s and not in %s or %s: %s" % (allEsrVersions[1], allEsrVersions[0], mainVersion, rollup_to_esr2 - rollup_to_esr1 - rollup_to_main))

        # rollup-to-esr1
        if rollup_to_esr1 - rollup_to_esr2 - rollup_to_main:
            eprint("Bugs that are only in %s and not in %s or %s: %s" % (allEsrVersions[0], allEsrVersions[1], mainVersion, rollup_to_esr1 - rollup_to_esr2 - rollup_to_main))


    advisories = []
    references = []
    for b in nonRollUpBugs:
        if b['id'] in [1441468, 1587976] or (args.exclude is not None and str(b['id']) in args.exclude):
            continue
        
        attachment_text = getAdvisoryAttachment(b['id'])
        
        if Advisory.is_reference(attachment_text):
            references.append((Advisory.is_reference(attachment_text), b['id'], getSeverity(b)))
        else:
            advisories.append(Advisory(b, attachment_text))

    for r in references:
        target_adv = list(filter(lambda a: a.id == r[0], advisories))[0]
        target_adv.ids.append(r[1])
        target_adv.severity = getMaxSeverity(target_adv.severity, r[2])
        eprint("Ensure that the reporter for %s is the same as %s - if not, add the reporter of %s in the yml manually. bmo %s,%s" % (r[1], target_adv.id, r[1], target_adv.id, r[1]))


    if len(sharedRollupBugs) == 1:
        b = sharedRollupBugs[0]
        if (args.exclude is None or str(b['id']) not in args.exclude):
            try:
                advisories.append(Advisory(b, getAdvisoryAttachment(b['id'])))
            except:
                raise Exception("Could not find an advisory for %s which is the only bug in the shared rollup." % b['id'])
            sharedRollupBugs = []

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
        for each_id in a.ids:
            print("      - url:", each_id)

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
    doRollups(sharedRollupBugs,
        "Firefox " + mainVersion + " and Firefox ESR " + esrVersion,
        "Firefox " + str(int(mainVersion)-1) + " and Firefox ESR " + str(float(esrVersion)-.1))
    if not args.esr:
    # Rollup Bug for Main Only 
        doRollups(version_specific_rollups,
            "Firefox " + mainVersion,
            "Firefox " + str(int(mainVersion)-1))
    else:
    # Rollup bug for ESR only
        doRollups(version_specific_rollups,
            "Firefox ESR " + esrVersion,
            "Firefox ESR " + str(float(esrVersion) - .1))