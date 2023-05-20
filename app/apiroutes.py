# apiroutes.py - a python flask modules that contains the API routes for various DNS tasks
#
# desc: we use the Flask framework to build the API
# desc: we use the socket module to perform the DNS lookups & the dns.resolver module to perform the SPF lookup
# desc: we pull in security functions from the security.py module to check for malicious domains
# desc: we return JSON objects for each API call
# todo: NS, CNAME, MX, DNS Propogation, DNSSEC enabled (whois or dig), SAA
# for dnssec: https://stackoverflow.com/questions/26137036/programmatically-check-if-domains-are-dnssec-protected
#
# author: Matthew Evans
# last edit: May 19, 2023

import socket
import re
import dns.resolver
import globalvars as gv
from app import app
from app.security import checkinversion, checkspamhaus, validdomain, validptr

# let's set a sane timeout for the socket module
socket.timeout(2)


# this is a typical A lookup, domain -> ip address
# we use a regular expression to validate the input
# we use the fullmatch method to ensure that the entire string matches the regex
# and the re.IGNORECASE flag to make the regex case-insensitive
@app.route('/api/a/<fqdn>', methods=['GET'])
def dnsapi(fqdn):

    if validdomain(fqdn):

        checkinversion(fqdn)

        if not checkinversion(fqdn):
            try:
                addr = socket.gethostbyname(fqdn)
                return {
                    "hostname": fqdn,
                    "addr": addr,
                }
            except socket.gaierror:
                print(gv.WARN + "dnsapi: %s does not resolve" % fqdn)
                return {
                    "error": "error in backend lookup, please notify the administrator"
                }
        else:
            print(gv.WARN + "%s found on malware list" % fqdn)
            return {
                "error": "domain {} found on malware list".format(fqdn)
            }
    else:
        print(gv.WARN  + "dnsapi: %s is an invalid domain" % fqdn)
        return {
            "error": "invalid domain provided, please check the address"
        }


# this function will perform a PTR "reverse" lookup on an IP address, i.e. ip -> fqdn
# we use a regex to make sure the input is valid and somewhat sanitized
# we call the checkspamhaus function to see if the IP address is on the spamhaus dnsbl list
# we return one of three key:value pairs:
#   ptr: the IP address
#   result: success
#   error: the domain is on spamhaus dnsbl list or the backend lookup failed for some reason
@app.route('/api/ptr/<ptr>', methods=['GET'])
def dnsptr(ptr):

    if validptr(ptr):

        checkspamhaus(ptr)

        if not checkspamhaus(ptr):
            try:
                ptrresult = socket.gethostbyaddr(ptr)
                return {
                    "ptr": ptr,
                    "result": ptrresult[0]
                 }
            except socket.gaierror:
                print(gv.WARN + "dnsptr: %s does not resolve" % ptr)
                return {
                    "error": "error in backend lookup, please notify the administrator"
                }
        else:
            print(gv.WARN + "dnsptr: %s found on dnsbl list" % ptr)
            return {
                "error": "domain {} found on spamhaus dnsbl list".format(ptr)
            }
    else:
        print(gv.WARN + "dnsptr: %s is an invalid ip" % ptr)
        return {
            "error": "invalid IP provided, please check the address"
        }


# this function will perform a DNS TXT lookup on a domain name, searching for the SPF record
# we check against a regex to make sure the input is valid and somewhat sanitized
# it will return a JSON object with the SPF record if found
# before executing anything, we check the user provided domain against a malware list
@app.route('/api/spf/<spfdomain>', methods=['GET'])
def spfapi(spfdomain):

    if validdomain(spfdomain):

        checkinversion(spfdomain)

        if not checkinversion(spfdomain):
            try:
                test_spf = dns.resolver.resolve(spfdomain, 'TXT')
                for rr in test_spf:
                    if "v=spf1" in rr.to_text():
                        result = rr.to_text()
                        return {
                            "spf": spfdomain,
                            "result": result.replace('"', '')  # the result has some weird double quotes, so we remove them
                        }

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                print(gv.WARN + "spfapi: %s failed the dns lookup" % spfdomain)
                return {
                    "error": "SPF record not found for domain {}".format(spfdomain)
                }


# this function will perform a DNS TXT lookup on a domain name, searching for the DMARC record
# we check against a regex to make sure the input is valid and somewhat sanitized
# it will return a JSON object with the DMARC record if found
# before executing anything, we check the user provided domain against a malware list
@app.route('/api/dmarc/<dmarcdomain>', methods=['GET'])
def dmarcapi(dmarcdomain):

    if validdomain(dmarcdomain):

        checkinversion(dmarcdomain)

        if not checkinversion(dmarcdomain):
            try:
                test_dmarc = dns.resolver.resolve("_dmarc." + dmarcdomain, 'TXT')
                for rr in test_dmarc:
                    if "v=DMARC1" in rr.to_text():
                        result = rr.to_text()
                        return {
                            "dmarc": dmarcdomain,
                            "result": result.replace('"', '')  # the result has some weird double quotes, so we remove them
                        }

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                # print(gv.WARN + "dmarcapi: %s failed the dns lookup" % dmarcdomain)
                return {
                    "error": "DMARC record not found for domain {}".format(dmarcdomain)
                }
        else:
            print(gv.WARN + "dmarcapi: %s found on malware list" % dmarcdomain)
            return {
                "error": "domain {} found on malware list".format(dmarcdomain)
            }


# this is a quick check for a dkim lookup with no selector provided
@app.route('/api/dkim/<dkim_domain_no_select>', methods=['GET'])
def dkimnoselector(dkim_domain_no_select):
    return {
        "error": "please provide a selector",
        "like so": "/api/dkim/" + dkim_domain_no_select + "/selector1"
    }


# this function will perform a DNS TXT lookup on a domain name, searching for the DKIM record
# we check against a regex to make sure the input is valid and somewhat sanitized
# it will return a JSON object with the DKIM record if found
@app.route('/api/dkim/<dkimdomain>/<selector>', methods=['GET'])
def dkimapi(dkimdomain, selector):

    if validdomain(dkimdomain):

        checkinversion(dkimdomain)

        if not checkinversion(dkimdomain):
            try:
                test_dkim = dns.resolver.resolve(selector + "._domainkey." + dkimdomain, 'TXT')
                for rr in test_dkim:
                    if "v=DKIM1" or "k=rsa" in rr.to_text():
                        result = rr.to_text()
                        return {
                            "dkim": dkimdomain,
                            "result": result.replace('"', '')  # the result has some weird double quotes, so we remove them
                        }
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                return {
                        "error": "DKIM record not found for domain {}".format(dkimdomain)
                    }
        else:
            print(gv.WARN + "dkimapi: %s found on malware list" % dkimdomain)
            return {
                "error": "domain {} found on malware list".format(dkimdomain)
            }
