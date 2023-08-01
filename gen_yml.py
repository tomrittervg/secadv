#!/usr/bin/env python3

from __future__ import print_function

import re
import sys
import base64
import datetime
import requests
import argparse
import itertools

try:
    from apikey import APIKEY
except:
    APIKEY = None

from gen_queries import getPriorVersion, versionToESRs, nonRollupList, rollupListMainAndESR, rollupListMainOnly, rollupListMain, rollupListESROnly, rollupListESR
from yml_utils import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a security release .yml')
    parser.add_argument('--verbose', '-v', action='store_true', help='print(out debugging info')
    parser.add_argument('--esr', action='count', default=0, help='Generate the ESR document for the given full version. Specify twice to generate for the second ESR version of a release.')
    parser.add_argument('--exclude', action='append', help='Bug IDs to exclude from checks about attachments')
    parser.add_argument('--allow-single', action='store_true', help='Allow single bug in rollups')
    parser.add_argument('version', help='Version to generate queries for. Do not give an ESR version; give the normal version and specify --esr')
    args = parser.parse_args(sys.argv[1:])
    if not APIKEY:
        eprint("API Key not defined in apikey.py")
        eprint("Fill that in with an API Key able to access security bugs.")
        sys.exit(1)
    if float(args.version) != int(float(args.version)) and not args.esr:
        eprint("This is a dot-release. If this is an ESR release, be sure to put the full version and --esr")

    mainVersion = args.version
    allEsrVersions = versionToESRs(args.version)
    if len(allEsrVersions) > 1:
        assert len(allEsrVersions) <= 2
        if args.esr <= len(allEsrVersions):
            esrVersion = str(allEsrVersions[args.esr - 1])
        else:
            eprint("--esr was specified more times than we have ESR versions to generate")
            sys.exit(1)
    else:
        esrVersion = allEsrVersions[0]
    targetVersion = esrVersion if args.esr else mainVersion
    eprint("Generating advisories for Version", targetVersion, ("(which is an ESR release)" if args.esr else ""))

    # -------------------------------------------------------------
    # Figure out the rollup situation
    # This is easy if there is only one ESR version and hard if there are two.
    # With one ESR, bugs will either be non-rollup, rollup-to-main, rollup-to-esr, or rollup-to-main-and-esr
    # With two ESRs, bugs could be non-rollup, rollup-to-main, rollup-to-esr1, rollup-to-esr2, rollup-to-main-and-esr1, rollup-to-main-and-esr2, rollup-to-esr1-and-esr2, or rollup-to-main-and-esr1-and-esr2

    # Non-rollup bugs
    nonRollUpBugs = doBugRequest(nonRollupList(targetVersion, mainVersion, args.esr).replace("buglist.cgi", "rest/bug") + "&api_key=" + APIKEY)
    # Rollup bugs
    rollUpBugsMain = doBugRequest(rollupListMain(mainVersion) + "&api_key=" + APIKEY)
    rollUpBugsESR1 = doBugRequest(rollupListESR(allEsrVersions[0]) + "&api_key=" + APIKEY)
    if len(allEsrVersions) > 1:
        rollUpBugsESR2 = doBugRequest(rollupListESR(allEsrVersions[1]) + "&api_key=" + APIKEY)
    else:
        rollUpBugsESR2 = []
    allBugsById = {b['id']: b for b in itertools.chain(nonRollUpBugs, rollUpBugsMain, rollUpBugsESR1, rollUpBugsESR2)}

    non_rollup = set(b['id'] for b in nonRollUpBugs)
    rollup_to_main = set(b['id'] for b in rollUpBugsMain)
    rollup_to_esr1 = set(b['id'] for b in rollUpBugsESR1)
    rollup_to_esr2 = set(b['id'] for b in rollUpBugsESR2)
    rollup_to_main_and_esr1 = rollup_to_main.intersection(rollup_to_esr1)
    rollup_to_main_and_esr2 = rollup_to_main.intersection(rollup_to_esr2)
    rollup_to_esr1_and_esr2 = rollup_to_esr1.intersection(rollup_to_esr2)
    rollup_to_main_and_esr1_and_esr2 = rollup_to_main.intersection(rollup_to_esr1).intersection(rollup_to_esr2)

    rollupCalls = []

    # rollup-to-main-and-esr1-and-esr2
    if rollup_to_main_and_esr1_and_esr2:
        eprint("Bugs that are in all three %s, %s, and %s: %s" % (mainVersion, allEsrVersions[0], allEsrVersions[1], rollup_to_main_and_esr1_and_esr2))
        rollupCalls.append(
            (
                sorted(rollup_to_main_and_esr1_and_esr2),
                f"Firefox {mainVersion}, Firefox ESR {allEsrVersions[0]}, Firefox ESR {allEsrVersions[1]}, Thunderbird {allEsrVersions[0]}, and Thunderbird {allEsrVersions[1]}",
                f"Firefox {getPriorVersion(mainVersion)}, Firefox ESR {getPriorVersion(allEsrVersions[0])}, Firefox ESR {getPriorVersion(allEsrVersions[1])}, Thunderbird {getPriorVersion(allEsrVersions[0])}, and Thunderbird {getPriorVersion(allEsrVersions[1])}",
            )
        )

    # rollup-to-main-and-esr1
    if (not args.esr or args.esr == 1) and (rollup_to_main_and_esr1 - rollup_to_esr2):
        eprint("Bugs that are only in %s and %s: %s" % (mainVersion, allEsrVersions[0], rollup_to_main_and_esr1 - rollup_to_esr2))
        rollupCalls.append(
            (
                sorted(rollup_to_main_and_esr1 - rollup_to_esr2),
                f"Firefox {mainVersion}, Firefox ESR {allEsrVersions[0]}, and Thunderbird {allEsrVersions[0]}",
                f"Firefox {getPriorVersion(mainVersion)}, Firefox ESR {getPriorVersion(allEsrVersions[0])}, and Thunderbird {getPriorVersion(allEsrVersions[0])}",
            )
        )

    # rollup-to-main-and-esr2
    if (not args.esr or args.esr == 2) and (rollup_to_main_and_esr2 - rollup_to_esr1):
        eprint("Bugs that are only in %s and %s: %s" % (mainVersion, allEsrVersions[1], rollup_to_main_and_esr2 - rollup_to_esr1))
        rollupCalls.append(
            (
                sorted(rollup_to_main_and_esr2 - rollup_to_esr1),
                f"Firefox {mainVersion}, Firefox ESR {allEsrVersions[1]}, and Thunderbird {allEsrVersions[1]}",
                f"Firefox {getPriorVersion(mainVersion)}, Firefox ESR {getPriorVersion(allEsrVersions[1])}, and Thunderbird {getPriorVersion(allEsrVersions[1])}",
            )
        )

    # rollup-to-main
    if not args.esr and (rollup_to_main - rollup_to_esr1 - rollup_to_esr2):
        eprint("Bugs that are only in %s and not in either ESR: %s" % (mainVersion, rollup_to_main - rollup_to_esr1 - rollup_to_esr2))
        rollupCalls.append(
            (
                sorted(rollup_to_main - rollup_to_esr1 - rollup_to_esr2),
                f"Firefox {mainVersion}",
                f"Firefox {getPriorVersion(mainVersion)}",
            )
        )

    # rollup-to-esr1-and-esr2
    if args.esr and (rollup_to_esr1_and_esr2 - rollup_to_main):
        eprint("Bugs that are in only the ESRs %s and %s: %s" % (allEsrVersions[0], allEsrVersions[1], rollup_to_esr1_and_esr2 - rollup_to_main))
        rollupCalls.append(
            (
                sorted(rollup_to_esr1_and_esr2 - rollup_to_main),
                f"Firefox ESR {allEsrVersions[0]}, Firefox ESR {allEsrVersions[1]}, Thunderbird {allEsrVersions[0]}, and Thunderbird {allEsrVersions[1]}",
                f"Firefox ESR {getPriorVersion(allEsrVersions[0])}, Firefox ESR {getPriorVersion(allEsrVersions[1])}, Thunderbird {getPriorVersion(allEsrVersions[0])}, and Thunderbird {getPriorVersion(allEsrVersions[1])}",
            )
        )

    # rollup-to-esr1
    if args.esr == 1 and (rollup_to_esr1 - rollup_to_esr2 - rollup_to_main):
        eprint("Bugs that are only in %s and not in %s or %s: %s" % (allEsrVersions[0], allEsrVersions[1], mainVersion, rollup_to_esr1 - rollup_to_esr2 - rollup_to_main))
        rollupCalls.append(
            (
                sorted(rollup_to_esr1 - rollup_to_esr2 - rollup_to_main),
                f"Firefox ESR {allEsrVersions[0]} and Thunderbird {allEsrVersions[0]}",
                f"Firefox ESR {getPriorVersion(allEsrVersions[0])}, and Thunderbird {getPriorVersion(allEsrVersions[0])}",
            )
        )

    # rollup-to-esr2
    if args.esr == 2 and (rollup_to_esr2 - rollup_to_esr1 - rollup_to_main):
        eprint("Bugs that are only in %s and not in %s or %s: %s" % (allEsrVersions[1], allEsrVersions[0], mainVersion, rollup_to_esr2 - rollup_to_esr1 - rollup_to_main))
        rollupCalls.append(
            (
                sorted(rollup_to_esr2 - rollup_to_esr1 - rollup_to_main),
                f"Firefox ESR {allEsrVersions[1]} and Thunderbird {allEsrVersions[1]}",
                f"Firefox ESR {getPriorVersion(allEsrVersions[1])}, and Thunderbird {getPriorVersion(allEsrVersions[1])}",
            )
        )

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

    filteredRollupCalls = []
    for rollupBugs, versions, priorVersions in rollupCalls:
        if len(rollupBugs) == 1:
            b = rollupBugs[0]
            if args.exclude is None or str(b) not in args.exclude:
                try:
                    advisories.append(Advisory(allBugsById[b], getAdvisoryAttachment(b)))
                except:
                    if not args.allow_single:
                        raise Exception(f"Could not find an advisory for {b} which is the only bug in rollup for {versions}.")
                    else:
                        filteredRollupCalls.append((rollupBugs, versions, priorVersions))
        else:
            filteredRollupCalls.append((rollupBugs, versions, priorVersions))

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

        if len(buglist) == 1 and not args.allow_single:
            raise Exception("We shouldn't be here for a single bug.")

        if len(buglist) == 1:
            bug_str = "bug"
            some_str = "this"
        else:
            bug_str = "bugs"
            some_str = "some of these"

        rollupIDs = []
        rollupReporters = set()
        rollupMaxSeverity = "low"
        for b_id in buglist:
            b = allBugsById[b_id]
            rollupIDs.append(b_id)
            name = cleanUpRealName(b['creator_detail']['real_name'])
            if name in ["Christian Holler", "Jason Kratzer", "Tyson Smith", "Jesse Schwartzentruber"]:
                rollupReporters.add("the Mozilla Fuzzing Team")
            elif name not in ["Treeherder Bug Filer"]:
                rollupReporters.add(name)
            try:
                rollupMaxSeverity = getMaxSeverity(rollupMaxSeverity, getSeverity(b))
            except:
                pass

        description = f"Memory safety {bug_str} present in {priorVersionTitle}. {some_str.capitalize()} {bug_str} showed evidence of memory corruption and we presume that with enough effort {some_str} could have been exploited to run arbitrary code."
        print("  CVE-XXX-rollup:")
        print("    title: Memory safety", bug_str, "fixed in", versionTitle)
        print("    impact:", rollupMaxSeverity)
        print("    reporter:", ", ".join(rollupReporters))
        print("    description: |")
        print("     ", description)
        print("    bugs:")
        print("      - url:", ", ".join([str(i) for i in rollupIDs]))
        print("        desc: Memory safety", bug_str, "fixed in", versionTitle)

    # Output all Rollup Bugs
    for rollupBugs, versions, priorVersions in filteredRollupCalls:
        doRollups(rollupBugs, versions, priorVersions)
