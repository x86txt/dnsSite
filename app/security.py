# this code will perform an API lookup against various security services, to see if the domain
# is malicious or not. It will return a JSON object with the results.
# todo: add 2nd malware_url list as backup
import dns.resolver
import io
import re
import socket
import urllib3
import globalvars as gv


# this function will check if the domain is expired or otherwise unavailable
# and halt any further progress if true
def checkexpired(domain):
    try:
        dns.resolver.resolve(domain)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return False


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
# NOTE: 196.16.11.222 can be used as a test address for a positive spamhaus match
# a true stops the ptr lookup and reports it was found on the spamhaus dnsbl list
# a false return allows the ptr lookup to proceed
# heavily inspired by: https://isc.sans.edu/diary/Querying+Spamhaus+for+IP+reputation/27320
def checkspamhaus(addr):

    if validptr(addr):
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


# this function will verify the domain matches the proper format via a regex compare
def validdomain(domain):

    checkdomain = re.fullmatch(gv.fqdnregex, domain, flags=re.ASCII | re.IGNORECASE)

    if checkdomain:
        return True
    else:
        return False


# this function will verify the IP address matches the proper format via a regex compare
def validptr(ptr):

    checkptr = re.fullmatch(gv.ptrregex, ptr, flags=re.ASCII)

    if checkptr:
        return True
    else:
        return False

