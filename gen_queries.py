#!/usr/bin/env python3

import sys
import argparse

"""
To update this function when we reach a new ESR, just add the new ESR version at the end of knownESRs.
Then add some new expected values to the expected variable in sanityCheck to make sure it works as expected.
Hopefully no code update is needed.

You may wonder why we have the versions as strings as the reurn from this function.
It's because 68.10 is mathematically equal to 68.1 but they are different versions.
"""
def versionToESRs(version):
    version = int(version)

    knownESRs = [60, 68, 78, 91, 102, 115, 128]
    twoESRVersions = []
    for x in knownESRs:
        twoESRVersions.append(x)
        twoESRVersions.append(x+1)
        # We have a three-release overlap post-78 due to shortened release cycles
        if x >= 78:
            twoESRVersions.append(x+2)
    for x in range(131, 137):
        twoESRVersions.append(x)

    twoESRs = True if version in twoESRVersions else False
    subsetOfESRs = [x for x in knownESRs if x <= version]

    if twoESRs:
        firstESRPointRelease = str(subsetOfESRs[-2]) + "." + str(version - subsetOfESRs[-2])
        secondESRPointRelease = str(subsetOfESRs[-1]) + "." + str(version - subsetOfESRs[-1])
        return [firstESRPointRelease, secondESRPointRelease]
    else:
        pointRelease = str(subsetOfESRs[-1]) + "." + str(version - subsetOfESRs[-1])
        return [pointRelease]

def getPriorVersion(version):
    if "." in version:
        return f'{version.split(".")[0]}.{int(version.split(".")[1]) - 1}'
    else:
        return str(int(version) - 1)

def sanityCheck():
    expected = [
        (68, ["60.8", "68.0"]),
        (69, ["60.9", "68.1"]),
        (70, ["68.2"]),
        (71, ["68.3"]),
        (72, ["68.4"]),
        (73, ["68.5"]),
        (74, ["68.6"]),
        (75, ["68.7"]),
        (76, ["68.8"]),
        (77, ["68.9"]),
        (78, ["68.10", "78.0"]),
        (79, ["68.11", "78.1"]),
        (80, ["68.12", "78.2"]),
        (81, ["78.3"]),
        (129, ["115.14", "128.1"]),
        (132, ["115.17", "128.4"]),
        (136, ["115.21", "128.8"]),
        (137, ["128.9"])
    ]
    for e in expected:
        if versionToESRs(e[0]) != e[1]:
            print("Sanity Check: Did not match versionToESRs(" + str(e[0]) + ") ==", e[1], "Got", versionToESRs(e[0]))
            sys.exit(1)





#------------------------
def toAssign(version, primaryVersion, esr):
    if esr:
        return toAssignESR(version, primaryVersion)
    else:
        return toAssignMain(version)
def toAssignMain(version):
    prior = getPriorVersion(version).replace(".", "")
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    \
    "&f2=cf_status_firefox" + prior + "&o2=nowords&v2=fixed%20verified%20disabled%20unaffected" + \
    \
    "&f5=cf_status_firefox" + version + "&o5=anywords&v5=fixed%20verified" + \
    \
    "&f9=status_whiteboard&o9=notsubstring&v9=adv-main" + version + \
    \
    "&f11=OP&j11=OR" + \
    "&f12=keywords&o12=substring&v12=sec-" + \
    "&f13=bug_group&o13=substring&v13=core-security" + \
    "&f14=CP"

def toAssignESR(esrVersion, primaryVersion):
    esrBaseVersion = esrVersion.split(".")[0]
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    \
    "&f2=cf_tracking_firefox_esr" + esrBaseVersion + "&o2=equals&v2=" + primaryVersion + "%2B" + \
    \
    "&f5=status_whiteboard&o5=notsubstring&v5=adv-esr" + esrVersion + \
    \
    "&f7=OP&j7=OR" + \
    "&f8=keywords&o8=substring&v8=sec-" + \
    "&f9=bug_group&o9=substring&v9=core-security" + \
    "&f10=CP"


#------------------------    
def toWrite(version, primaryVersion, esr):
    if esr:
        return toWriteESR(version, primaryVersion)
    else:
        return toWriteMain(version)
def toWriteMain(version):
    prior = getPriorVersion(version).replace(".", "")
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    \
    "&f2=cf_status_firefox" + prior + "&o2=nowords&v2=fixed%20verified%20disabled%20unaffected" + \
    \
    "&f5=cf_status_firefox" + version + "&o5=anywords&v5=fixed%20verified" + \
    \
    "&f9=status_whiteboard&o9=substring&v9=adv-main" + version + "%2B" + \
    "&f10=status_whiteboard&o10=notsubstring&v10=adv-main" + version + "%2Br" + \
    \
    "&f13=attachments.description&o13=equals&v13=advisory.txt&n13=1" + \
    \
    "&f15=OP&j15=OR" + \
    "&f16=keywords&o16=substring&v16=sec-" + \
    "&f17=bug_group&o17=substring&v17=core-security" + \
    "&f18=CP"

def toWriteESR(esrVersion, primaryVersion):
    esrBaseVersion = esrVersion.split(".")[0]
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    \
    "&f2=cf_tracking_firefox_esr" + esrBaseVersion + "&o2=equals&v2=" + primaryVersion + "%2B" + \
    \
    "&f5=status_whiteboard&o5=substring&v5=adv-esr" + esrVersion + "%2B" + \
    "&f6=status_whiteboard&o6=notsubstring&v6=adv-esr" + esrVersion + "%2Br" + \
    \
    "&f9=attachments.description&o9=equals&v9=advisory.txt&n9=1" + \
    \
    "&f11=OP&j11=OR" + \
    "&f12=keywords&o12=substring&v12=sec-" + \
    "&f13=bug_group&o13=substring&v13=core-security" + \
    "&f14=CP"


#------------------------
def rollupList(version, primaryVersion, esr):
    if esr:
        return rollupListESR(version)
    else:
        return rollupListMain(version)
def rollupListMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f1=status_whiteboard&o1=substring&v1=adv-main" + version + "%2Br"

def rollupListESR(esrVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f1=status_whiteboard&o1=substring&v1=adv-esr" + esrVersion + "%2Br"

def rollupListMainAndESR(primaryVersion, esrVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + primaryVersion + "%2Br" + \
    "&f3=status_whiteboard&o3=substring&v3=adv-esr" + esrVersion + "%2Br"

def rollupListMainOnly(primaryVersion, allEsrVersions):
    s = "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + primaryVersion + "%2Br" + \
    "&f3=status_whiteboard&o3=notsubstring&v3=adv-esr" + allEsrVersions[0] + "%2Br"
    if len(allEsrVersions) > 1:
        s += "&f4=status_whiteboard&o4=notsubstring&v4=adv-esr" + allEsrVersions[1] + "%2Br"
    return s

def rollupListMain(primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f1=status_whiteboard&o1=substring&v1=adv-main" + primaryVersion + "%2Br"

def rollupListESROnly(primaryVersion, esrVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=notsubstring&v2=adv-main" + primaryVersion + "%2Br" + \
    "&f3=status_whiteboard&o3=substring&v3=adv-esr" + esrVersion + "%2Br"

#------------------------
def allAdvisories(version, primaryVersion, esr):
    if esr:
        return allAdvisoriesESR(version, primaryVersion)
    else:
        return allAdvisoriesMain(version)
def allAdvisoriesMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B"
def allAdvisoriesESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "%2B"

#------------------------
def nonRollupList(version, primaryVersion, esr):
    if esr:
        return nonRollupListESR(version, primaryVersion)
    else:
        return nonRollupListMain(version)
def nonRollupListMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B" \
    "&f3=status_whiteboard&o3=notsubstring&v3=adv-main" + version + "%2Br"
def nonRollupListESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "%2B" + \
    "&f3=status_whiteboard&o3=notsubstring&v3=adv-esr" + esrVersion + "%2Br"

#------------------------
def rejected(version, primaryVersion, esr):
    if esr:
        return rejectedESR(version, primaryVersion)
    else:
        return rejectedMain(version)
def rejectedMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "-" 
def rejectedESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "-"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Print Bugzilla queries for Security Advisories')
    parser.add_argument('--verbose', '-v', action='store_true', help='Print out the extra, less-needed queries')
    parser.add_argument('version', help='Version to generate queries for')
    args = parser.parse_args(sys.argv[1:])

    sanityCheck()
    primaryVersion = args.version
    versions = [primaryVersion] + versionToESRs(primaryVersion)
    print("Calculating versions", versions)
    

    for i in range(len(versions)):
        version = versions[i]
        print("------------------------------------------------------------")
        print("Version:", version)
        print("")

        print("Whiteboard tags to assign:")
        print(toAssign(version, primaryVersion, i != 0))
        print("")

        print("Advisories to write:")
        print(toWrite(version, primaryVersion, i != 0))
        print("")

        print("Roll-up list:")
        print(rollupList(version, primaryVersion, i != 0))
        print("")

        if not args.verbose:
            continue

        print("All tagged advisories:")
        print(allAdvisories(version, primaryVersion, i != 0))
        print("")

        print("Non-rollup advisories:")
        print(nonRollupList(version, primaryVersion, i != 0))
        print("")

        if i > 0:
            print("ESR-Specific Rollups:")
            print(rollupListESROnly(primaryVersion, version))
        else:
            print("Version-Specific Rollups:")
            print(rollupListMainOnly(primaryVersion, versions[1:]))
        print("")

        print("Advisories considered and rejected:")
        print(rejected(version, primaryVersion, i != 0))
        print("")
