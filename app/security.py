# this code will perform an API lookup against various security services, to see if the domain
# is malicious or not. It will return a JSON object with the results.
# todo: add 2nd malware_url list as backup
import io
import re
import socket
import sys, getopt, argparse
import urllib3

fqdnregex = '^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$'
ptrregex = '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'


# this function will check the domain against a list of known malicious domains
# if it finds a match, it will return True and deny the dns lookup
def checkinversion(domain):
    http = urllib3.PoolManager()
    malware_url = 'https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_light.txt'
    r = http.request('GET', malware_url)
    if r.status == 200:
        data = io.StringIO(r.data.decode('utf-8'))
        for line in data:
            regex = re.compile("^" + domain + "$")
            if regex.match(line):
                return True
            return False
    else:
        return False


# this function will check the IP address against the spamhaus dnsbl list
# if it finds a match, it will return True, report it to the user, and deny the ptr lookup
# 196.16.11.222 can be used as a test address for a positive spamhaus match
# a true stops the ptr lookup and reports it was found on the spamhaus dnsbl list
# a false return allows the ptr lookup to proceed
def checkspamhaus(addr):

    # we need to make sure our input is valid and somewhat sanitized
    validptr = re.fullmatch(ptrregex, addr, flags=re.ASCII | re.IGNORECASE)

    if validptr:
        try:
            # reverse the IP address and append the spamhaus domain
            hostname = ".".join(addr.split(".")[::-1]) + ".zen.spamhaus.org"

            # here is where we do the actual PTR record lookup on the IP address
            try:
                socket.gethostbyname(hostname)
                return True
            except socket.gaierror:
                return False

        # if we encounter an error trying to construct the hostname, we return False
        except ValueError:
            return False

