import socket
import re
from app import app
from app.security import checkinversion, checkspamhaus

fqdnregex = '^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$'
ptrregex = '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
emailregex = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

socket.timeout(5)


# this will allow people to call the API directly, it will return a JSON object
# we use a regular expression to validate the input
# we use the fullmatch method to ensure that the entire string matches the regex
# and the re.IGNORECASE flag to make the regex case-insensitive
@app.route('/api/a/<fqdn>', methods=['GET'])
def dnsapi(fqdn):

    validfqdn = re.fullmatch(fqdnregex, fqdn, flags=re.ASCII | re.IGNORECASE)

    if validfqdn:
        checkinversion(fqdn)
        if not checkinversion(fqdn):
            try:
                addr = socket.gethostbyname(fqdn)
                return {
                    "hostname": fqdn,
                    "addr": addr,
                }
            except socket.gaierror:
                return {
                    "error": "error in backend lookup, please notify the administrator"
                }
        else:
            return {
                "error": "domain {} found on malware list".format(fqdn)
            }


# this function will perform a PTR "reverse" lookup on an IP address, i.e. IP to FQDN
# we use a regex to make sure the input is valid and somewhat sanitized
# we call the checkspamhaus function to see if the IP address is on the spamhaus dnsbl list
# we return one of three key:value pairs:
#   ptr: the IP address
#   result: success
#   error: the domain is on spamhaus dnsbl list or the backend lookup failed for some reason
@app.route('/api/ptr/<ptr>', methods=['GET'])
def dnsptr(ptr):
    validptr = re.fullmatch(ptrregex, ptr, flags=re.ASCII)
    if validptr:
        checkspamhaus(ptr)
        if not checkspamhaus(ptr):
            try:
                ptrresult = socket.gethostbyaddr(ptr)
                return {
                    "ptr": ptr,
                    "result": ptrresult[0]
                 }
            except socket.gaierror:
                return {
                    "error": "error in backend lookup, please notify the administrator"
                }
        else:
            return {
                "error": "domain {} found on spamhaus dnsbl list".format(ptr)
            }
    else:
        return {
            "error": "invalid IP provided, please check the address"
        }


@app.route('/api/email/<email>', methods=['GET'])
def emailapi(email):
    vemail = re.fullmatch(emailregex, email, flags=re.ASCII)