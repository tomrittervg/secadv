#!/usr/bin/env python

import sys
import argparse


def versionToESRs(version):
    if ((version - 68) % 8) == 0 or ((version - 68) % 8) == 1:
        # We're in the overlap range
        lastESRBase = version - 8 - ((version - 68) % 8)
        if ((version - 68) % 8) == 0:
            # This is the first release in the overlap, so only one ESR version, the old one
            return [lastESRBase + .8]
        else:
            # Second release in the overlap: two ESR versions
            return [lastESRBase + .9, (version - 1) + .1]
    else:
        pointRelease = float((version - 68) % 8)
        return [(version - pointRelease) + (pointRelease / 10)]


def sanityCheck():
    expected = [
        (68, [60.8]),
        (69, [60.9, 68.1]),
        (70, [68.2]),
        (71, [68.3]),
        (72, [68.4]),
        (73, [68.5]),
        (74, [68.6]),
        (75, [68.7]),
        (76, [68.8]),
        (77, [68.9, 76.1])
    ]
    for e in expected:
        if versionToESRs(e[0]) != e[1]:
            print(("Sanity Check: Did not match versionToESRs(" +
                   str(e[0]) + ") ==", e[1], "Got", versionToESRs(e[0])))
            sys.exit(1)

# ------------------------


def toAssign(version, primaryVersion, esr):
    if esr:
        return toAssignESR(version, primaryVersion)
    else:
        return toAssignMain(version)


def toAssignMain(version):
    version = str(version)
    last = str(int(version) - 1)
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
        "&f2=cf_status_firefox" + last + "&o2=nowordssubstr&v2=fixed%20verified%20unaffected%20disabled" + \
        "&f3=CP" + \
    \
        "&f4=OP&j4=OR" + \
        "&f5=cf_status_firefox" + version + "&o5=equals&v5=fixed" + \
        "&f6=cf_status_firefox" + version + "&o6=equals&v6=verified" + \
        "&f7=CP" + \
    \
        "&f8=OP" + \
        "&f9=status_whiteboard&o9=notsubstring&v9=adv-main" + version + \
        "&f10=CP"


def toAssignESR(version, primaryVersion):
    esrVersion = str(int(version))
    version = str(version)
    primaryVersion = str(primaryVersion)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
    \
        "&classification=Client%20Software" + \
        "&classification=Developer%20Infrastructure" + \
        "&classification=Components" + \
        "&classification=Other" + \
    \
        "&keywords=sec-%28.%2B%29&keywords_type=regexp" + \
    \
        "&f1=OP&j1=OR" + \
        "&f2=cf_tracking_firefox_esr" + esrVersion + "&o2=equals&v2=" + primaryVersion + "%2B" + \
        "&f3=CP" + \
    \
        "&f4=OP" + \
        "&f5=status_whiteboard&o5=notsubstring&v5=adv-esr" + version + \
        "&f6=CP"

# ------------------------


def toWrite(version, primaryVersion, esr):
    if esr:
        return toWriteESR(version, primaryVersion)
    else:
        return toWriteMain(version)


def toWriteMain(version):
    version = str(version)
    last = str(int(version) - 1)
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
        "&f2=cf_status_firefox" + last + "&o2=nowordssubstr&v2=fixed%20verified%20unaffected%20disabled" + \
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
        "&f14=CP"


def toWriteESR(version, primaryVersion):
    esrVersion = str(int(version))
    version = str(version)
    primaryVersion = str(primaryVersion)
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
        "&f2=cf_tracking_firefox_esr" + esrVersion + "&o2=equals&v2=" + primaryVersion + "%2B" + \
        "&f3=CP" + \
    \
        "&f4=OP" + \
        "&f5=status_whiteboard&o5=substring&v5=adv-esr" + version + "%2B" + \
        "&f6=status_whiteboard&o6=notsubstring&v6=adv-esr" + version + "%2Br" + \
        "&f7=CP" + \
    \
        "&f8=OP" + \
        "&f9=attachments.description&o9=equals&v9=advisory.txt&n9=1" + \
        "&f10=CP"

# ------------------------


def rollupList(version, primaryVersion, esr):
    if esr:
        return rollupListESR(version, primaryVersion)
    else:
        return rollupListMain(version)


def rollupListMain(version):
    version = str(version)
    last = str(int(version) - 1)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2Br" + \
        "&f3=CP"


def rollupListESR(version, primaryVersion):
    esrVersion = str(int(version))
    version = str(version)
    primaryVersion = str(primaryVersion)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-esr" + version + "%2Br" + \
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

# ------------------------


def allAdvisories(version, primaryVersion, esr):
    if esr:
        return allAdvisoriesESR(version, primaryVersion)
    else:
        return allAdvisoriesMain(version)


def allAdvisoriesMain(version):
    version = str(version)
    last = str(int(version) - 1)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B" \
        "&f3=CP"


def allAdvisoriesESR(version, primaryVersion):
    esrVersion = str(int(version))
    version = str(version)
    primaryVersion = str(primaryVersion)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-esr" + version + "%2B" + \
        "&f3=CP"

# ------------------------


def nonRollupList(version, primaryVersion, esr):
    if esr:
        return nonRollupListESR(version, primaryVersion)
    else:
        return nonRollupListMain(version)


def nonRollupListMain(version):
    version = str(version)
    last = str(int(version) - 1)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "%2B" \
        "&f3=status_whiteboard&o3=notsubstring&v3=adv-main" + version + "%2Br" + \
        "&f4=CP"


def nonRollupListESR(version, primaryVersion):
    esrVersion = str(int(version))
    version = str(version)
    primaryVersion = str(primaryVersion)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-esr" + version + "%2B" + \
        "&f3=status_whiteboard&o3=notsubstring&v3=adv-esr" + version + "%2Br" + \
        "&f4=CP"

# ------------------------


def rejected(version, primaryVersion, esr):
    if esr:
        return rejectedESR(version, primaryVersion)
    else:
        return rejectedMain(version)


def rejectedMain(version):
    version = str(version)
    last = str(int(version) - 1)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-main" + version + "-" \
        "&f3=CP"


def rejectedESR(version, primaryVersion):
    esrVersion = str(int(version))
    version = str(version)
    primaryVersion = str(primaryVersion)
    return "https://bugzilla.mozilla.org/buglist.cgi?query_format=advanced" + \
        "&f1=OP" + \
        "&f2=status_whiteboard&o2=substring&v2=adv-esr" + version + "-" + \
        "&f3=CP"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Print Bugzilla queries for Security Advisories')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print out the extra, less-needed queries')
    parser.add_argument('version', help='Version to generate queries for')
    args = parser.parse_args(sys.argv[1:])

    sanityCheck()
    primaryVersion = int(args.version)
    versions = [primaryVersion] + versionToESRs(primaryVersion)
    print(("Calculating versions", versions))

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
