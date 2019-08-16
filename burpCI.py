#! /usr/bin/env python3
# executes a scan on Burp Enterprise

import sys, os, argparse, requests, jinja2, validators, urllib3
from time import sleep

# constant variables
urllib3.disable_warnings() # due to poc environment

# environment variables, in this case you need these set, or part of the docker build
url = os.environ['BURPURL'] # url of burp environment https://burp.example.com:8443/api/
report_url = os.environ['BURPREPORTURL'] # url for reports at the end https://burp.example.come.com:8443/scans/
domain = os.environ['BURPSCANDOMAIN'] # used to restrict the sites we scan, don't want to scan something that isn't ours, i.e example.com

# these are the out of the box scan profiles from Burp Enterprise
scan_profiles = [
    {'name': 'Audit checks - all except JavaScript analysis', 'value': '1'}, 
    {'name': 'Audit checks - all except time-based detection methods', 'value': '2'}, 
    {'name': 'Audit checks - critical issues only', 'value': '3'}, 
    {'name': 'Audit checks - extensions only', 'value': '4'}, 
    {'name': 'Audit checks - light active', 'value': '5'}, 
    {'name': 'Audit checks - medium active', 'value': '6'}, 
    {'name': 'Audit checks - passive', 'value': '7'}, 
    {'name': 'Audit coverage - maximum', 'value': '8'}, 
    {'name': 'Audit coverage - thorough', 'value': '9'}, 
    {'name': 'Crawl limit - 10 minutes', 'value': '10'}, 
    {'name': 'Crawl limit - 30 minutes', 'value': '11'}, 
    {'name': 'Crawl limit - 60 minutes', 'value': '12'}, 
    {'name': 'Crawl strategy - faster', 'value': '13'}, 
    {'name': 'Crawl strategy - fastest', 'value': '14'}, 
    {'name': 'Crawl strategy - more complete', 'value': '15'}, 
    {'name': 'Crawl strategy - most complete', 'value': '16'}, 
    {'name': 'Minimize false negatives', 'value': '17'}, 
    {'name': 'Minimize false positives', 'value': '18'}, 
    {'name': 'Never stop audit due to application errors', 'value': '19'}, 
    {'name': 'Never stop crawl due to application errors', 'value': '20'}
    ]

# utility functions

def listscanprofiles():
    # return list of profiles that can be used in a scan

    print("The following scan profiles can be used:")
    print("Supply them in comma delimited for like this --profiles 1,2,3,4")
    
    for profile in scan_profiles:
        print("{}: {}".format(profile['value'], profile['name']))
    sys.exit(0)

def validateurls(urls):
    # validate the supplied urls are actually... urls

    for url in urls:
        if not validators.url(url):
            print("{} does not appear to be a valid url".format(url))
            sys.exit(1)
        if domain not in url:
            print("{} is not a valid domain to scan, limited to {}} domains".format(url, domain))
            sys.exit(1)

    return urls

def validatedomain(urls):
    # we don't want to scan things we don't own, so only the domain in the domain variable are allowed

    for url in urls:
        if domain not in url:
            print("{} is not a valid domain to scan, limited to {} domains".format(url, domain))
            sys.exit(1)

    return urls

def genprofiles(profiles):
    #  creates the list of profiles based on number values provided

    profilelist = []

    for x in profiles:
        for scan in scan_profiles:
            if scan['value'] == x:
                profilelist.append(scan['name'])
   
    if len(profilelist) > 0:
       return profilelist
    else:
        print("No profiles provided, or profiles not in list, use --list-scan-profiles to see available list")
        sys.exit(1)

def genbody(name, sites, profiles, username=None, password=None, exclude=None):
    # generates the body for the post request

    with open('scan-template.j2') as f:
        contents = f.read()

    template = jinja2.Template(contents)
    body = template.render(title=name, sites=sites, profiles=profiles, username=username, password=password, exclude=exclude)
    return body

def gensummary(report):
    # generates a summary of the number of issues by severity in the report

    sevlist = ["critical", "high", "medium", "low", "info"]
    counts = [ ]

    for severity in sevlist:
        count = 0
        for issue in report['issue_events']:
            # print(issue['issue'].keys())
            if issue['issue']['severity'] == severity:
                count += 1
        temp = { "severity": severity, "total": count }
        counts.append(temp)

    return counts

def printsummary(summary):
    # prints the summary totals of issues to console

    print("Issues found:")
    for item in summary:
        print("{}: {}".format(item['severity'], item['total']))
    
    return True
    
def buildstatus(summary, threshold):
    # used to fail a build if there are issues identified at or above the provided threshold.
    map = [ 
        { "threshold": "critical", "values": ["critical"] },
        { "threshold": "high", "values": ["critical", "high"] }, 
        { "threshold": "medium", "values": ["critical", "high", "medium"] }, 
        { "threshold": "low", "values": ["critical", "high", "medium", "low"] },
        { "threshold": "info", "values": ["critical", "high", "medium", "low", "info"] }
    ]

    check = {}
    for item in map:
        if item['threshold'] == threshold:
            check = item['values']
            break
    
    count = 0
    for severity in summary:
        if (severity['severity'] in check) and (severity['total'] > 0):
            count += severity['total']
            
    if count > 0:
        print("Build failed, {} issues exist above or equal requested threshold of {}".format(count, threshold))
        sys.exit(1)
    else:
        print("Build successful, no issues found above or equal to requested threshold.")
        sys.exit(0)

# request methods
def scanstatus(endpoint, scanref):
    # checks for scan status succeeded, or times out after 30 minutes. returns result of the scan.

    print("Checking status for Scan {}...".format(scanref))

    scanurl = endpoint + "/" + scanref
    res = requests.get(scanurl, verify=False).json()
    count = 0

    while (res['scan_status'] != "succeeded"):
        sleep(60)
        res = requests.get(scanurl, verify=False).json()
        count += 1
        print("Scan {} - Status: {}, Running Time: {} minutes".format(scanref, res['scan_status'], count))
        
        if count == 60:
            print("60 minutes have passed scan {} may gone off the rails, login to Burp and verify or cancel...".format(scanref))
            sys.exit(1)
            break
        
    return res

def scan(endpoint, config):
    # executes a scan, and returns the scan number

    try:
        res = requests.post(endpoint, data=config, verify=False)
        res.raise_for_status()
        scan = res.headers['location']
    except Exception as e:
        print("Something went horribly wrong: {}".format(e))
        sys.exit(1)

    print("Scan {} started....".format(scan))

    return scan


def __main__():
    # burp enterprise python ci script

    # grab args
    parser = argparse.ArgumentParser(description='Burp Enterprise PoC Python CI script')
    parser.add_argument('--key', '-k', dest='key', help='burp api key')
    parser.add_argument('--name', '-n', dest='name', help='name of the application, example: login app')
    parser.add_argument('--build', '-b', dest='build', help='build identifier/number')
    parser.add_argument('--sites', '-s', help='list of sites to scan, comma seperated list, example https://www.example.com/test,https://www.example.com/login')
    parser.add_argument('--profiles', dest='profiles', default='5,10', help='list of scan profiles to execute, example: 1,2,3,4.  To see list of profiles available, run --list-scan-profiles')
    parser.add_argument('--username', dest='username', help='username for authenticated scanning')
    parser.add_argument('--password', dest='password', help='password for authenticated scanning')
    parser.add_argument('--exclude', dest='exclude', help='optional list of urls to exclude from scan scope, comma seperated list')
    parser.add_argument('--threshold', dest='threshold', default='medium', choices=['critical','high','medium','low', 'info'], help='threshold to fail the build at')
    parser.add_argument('--list-scan-profiles', dest='scans', action='store_true', default=False, help='scan profile execute, use --list-scan-profiles to see the available list')
    parser.add_argument('--version', '-v', action='version', version='%(prog)s 0.8')
    args = parser.parse_args()
    
    # show list of scan configurations available
    if args.scans:
        listscanprofiles()
  
    # optional info
    if args.exclude:
        exclude = validateurls(args.exclude.split(','))
    else: 
        exclude = None

    # gather arguments and things to get this going
    scanname = args.name + " - " + args.build
    sites = validateurls(args.sites.split(',')) 
    sites = validatedomain(sites)
    profiles = genprofiles(args.profiles.split(','))
    endpoint = url + args.key + "/v0.1/scan"

    # go forth and scan
    body = genbody(scanname, sites, profiles, args.username, args.password, exclude)
    scanref = scan(endpoint, body)
    report = scanstatus(endpoint, scanref)
    print("Report available here: {}{}".format(report_url,scanref))
    summary = gensummary(report)
    printsummary(summary)
    buildstatus(summary, args.threshold)
    
if __name__ == '__main__':
    __main__()

 