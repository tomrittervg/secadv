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

    knownESRs = [60, 68, 78, 91, 102]
    twoESRVersions = []
    for x in knownESRs:
        twoESRVersions.append(x)
        twoESRVersions.append(x+1)
        # We have a three-release overlap post-78 due to shortened release cycles
        if x >= 78:
            twoESRVersions.append(x+2)

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
        return version.split(".")[0] + str(int(version.split(".")[1])-1)
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
        (81, ["78.3"])
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
    prior = getPriorVersion(version)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    \
    "&classification=Client%20Software" + \
    "&classification=Developer%20Infrastructure" + \
    "&classification=Components" + \
    "&classification=Other" + \
    \
    "&f1=OP" + \
    "&f2=cf_status_firefox" + prior + "&o2=nowordssubstr&v2=fixed%20verified%20unaffected%20disabled" + \
    "&f3=CP" + \
    \
    "&f4=OP&j4=OR" + \
    "&f5=cf_status_firefox" + version + "&o5=equals&v5=fixed" + \
    "&f6=cf_status_firefox" + version + "&o6=equals&v6=verified" + \
    "&f7=CP" + \
    \
    "&f8=OP" + \
    "&f9=status_whiteboard&o9=notsubstring&v9=adv-main" + version + \
    "&f10=CP" + \
    \
    "&f11=OP&j11=OR" + \
    "&f12=keywords&o12=regexp&v12=sec-%28.%2B%29" + \
    "&f13=bug_group&o13=substring&v13=%20core-security%20" + \
    "&f14=CP"

def toAssignESR(esrVersion, primaryVersion):
    esrBaseVersion = str(int(float(esrVersion)))
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    \
    "&classification=Client%20Software" + \
    "&classification=Developer%20Infrastructure" + \
    "&classification=Components" + \
    "&classification=Other" + \
    \
    "&f1=OP&j1=OR" + \
    "&f2=cf_tracking_firefox_esr" + esrBaseVersion + "&o2=equals&v2=" + primaryVersion + "%2B" + \
    "&f3=CP" + \
    \
    "&f4=OP" + \
    "&f5=status_whiteboard&o5=notsubstring&v5=adv-esr" + esrVersion + \
    "&f6=CP" + \
    \
    "&f7=OP&j7=OR" + \
    "&f8=keywords&o8=regexp&v8=sec-%28.%2B%29" + \
    "&f9=bug_group&o9=substring&v9=%20core-security%20" + \
    "&f10=CP"


#------------------------    
def toWrite(version, primaryVersion, esr):
    if esr:
        return toWriteESR(version, primaryVersion)
    else:
        return toWriteMain(version)
def toWriteMain(version):
    prior = getPriorVersion(version)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    \
    "&classification=Client%20Software" + \
    "&classification=Developer%20Infrastructure" + \
    "&classification=Components" + \
    "&classification=Other" + \
    \
    "&f1=OP" + \
    "&f2=cf_status_firefox" + prior + "&o2=nowordssubstr&v2=fixed%20verified%20unaffected%20disabled" + \
    "&f3=CP" + \
    \
    "&f4=OP&j4=OR" + \
    "&f5=cf_status_firefox" + version + "&o5=equals&v5=fixed" + \
    "&f6=cf_status_firefox" + version + "&o6=equals&v6=verified" + \
    "&f7=CP" + \
    \
    "&f8=OP" + \
    "&f9=status_whiteboard&o9=substring&v9=adv-main" + version + "%2B" + \
    "&f10=status_whiteboard&o10=notsubstring&v10=adv-main" + version + "%2Br" + \
    "&f11=CP" + \
    \
    "&f12=OP" + \
    "&f13=attachments.description&o13=equals&v13=advisory.txt&n13=1" + \
    "&f14=CP" + \
    \
    "&f15=OP&j15=OR" + \
    "&f16=keywords&o16=regexp&v16=sec-%28.%2B%29" + \
    "&f17=bug_group&o17=substring&v17=%20core-security%20" + \
    "&f18=CP"

def toWriteESR(esrVersion, primaryVersion):
    esrBaseVersion = str(int(float(esrVersion)))
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    \
    "&classification=Client%20Software" + \
    "&classification=Developer%20Infrastructure" + \
    "&classification=Components" + \
    "&classification=Other" + \
    \
    "&keywords=sec-%28.%2B%29&keywords_type=regexp" + \
    \
    "&f1=OP" + \
    "&f2=cf_tracking_firefox_esr" + esrBaseVersion + "&o2=equals&v2=" + primaryVersion + "%2B" + \
    "&f3=CP" + \
    \
    "&f4=OP" + \
    "&f5=status_whiteboard&o5=substring&v5=adv-esr" + esrVersion + "%2B" + \
    "&f6=status_whiteboard&o6=notsubstring&v6=adv-esr" + esrVersion + "%2Br" + \
    "&f7=CP" + \
    \
    "&f8=OP" + \
    "&f9=attachments.description&o9=equals&v9=advisory.txt&n9=1" + \
    "&f10=CP" + \
    \
    "&f11=OP&j11=OR" + \
    "&f12=keywords&o12=regexp&v12=sec-%28.%2B%29" + \
    "&f13=bug_group&o13=substring&v13=%20core-security%20" + \
    "&f14=CP"


#------------------------
def rollupList(version, primaryVersion, esr):
    if esr:
        return rollupListESR(version, primaryVersion)
    else:
        return rollupListMain(version)
def rollupListMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2Br" + \
    "&f3=CP"

def rollupListESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "%2Br" + \
    "&f3=CP"

def rollupListMainAndESR(primaryVersion, esrVersion):
    return "https://bugzilla.mozilla.org/rest/bug?" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + primaryVersion + "%2Br" + \
    "&f3=status_whiteboard&o3=substring&v3=adv-esr" + esrVersion + "%2Br" + \
    "&f4=CP"


def rollupListMainOnly(primaryVersion, esrVersion):
    return "https://bugzilla.mozilla.org/rest/bug?" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + primaryVersion + "%2Br" + \
    "&f3=status_whiteboard&o3=notsubstring&v3=adv-esr" + esrVersion + "%2Br" + \
    "&f4=CP"

def rollupListESROnly(primaryVersion, esrVersion):
    return "https://bugzilla.mozilla.org/rest/bug?" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=notsubstring&v2=adv-main" + primaryVersion + "%2Br" + \
    "&f3=status_whiteboard&o3=substring&v3=adv-esr" + esrVersion + "%2Br" + \
    "&f4=CP"

#------------------------
def allAdvisories(version, primaryVersion, esr):
    if esr:
        return allAdvisoriesESR(version, primaryVersion)
    else:
        return allAdvisoriesMain(version)
def allAdvisoriesMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B" \
    "&f3=CP"
def allAdvisoriesESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "%2B" + \
    "&f3=CP"

#------------------------
def nonRollupList(version, primaryVersion, esr):
    if esr:
        return nonRollupListESR(version, primaryVersion)
    else:
        return nonRollupListMain(version)
def nonRollupListMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B" \
    "&f3=status_whiteboard&o3=notsubstring&v3=adv-main" + version + "%2Br" + \
    "&f4=CP"
def nonRollupListESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "%2B" + \
    "&f3=status_whiteboard&o3=notsubstring&v3=adv-esr" + esrVersion + "%2Br" + \
    "&f4=CP"

#------------------------
def rejected(version, primaryVersion, esr):
    if esr:
        return rejectedESR(version, primaryVersion)
    else:
        return rejectedMain(version)
def rejectedMain(version):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "-" \
    "&f3=CP"
def rejectedESR(esrVersion, primaryVersion):
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    "&f1=OP" + \
    "&f2=status_whiteboard&o2=substring&v2=adv-esr" + esrVersion + "-" + \
    "&f3=CP"

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

        print("Advisories considered and rejected:")
        print(rejected(version, primaryVersion, i != 0))
        print("")
