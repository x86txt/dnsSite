import socket
import re
from flask import render_template, flash, request, Markup, redirect, url_for
from app import app
from app.forms import InputForm


# this is our main page, nothing fancy here
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='welcome to dnsTools!')


# this is for a typical A record lookup, we grab the domain from the query string if it exists
@app.route('/dns', methods=['GET', 'POST'])
def dns():
    form = InputForm()
    if request.method == 'POST' and form.validate():
        addr = socket.gethostbyname(form.hostname.data)
        hostname = form.hostname.data
        flash(Markup('dns lookup requested for domain name or FQDN {}'.format(
            form.hostname.data) + ': the result is ' + addr), 'success')
        return redirect(url_for('result', addr=addr, hostname=hostname))
    return render_template('dns.html', title='dns lookup', form=form)


# this will allow people to call the API directly, it will return a JSON object
# this is not a secure way to do this, but it's a good example of how to do it
# we use a regular expression to validate the input
# we also use the fullmatch method to ensure that the entire string matches the regex
# we also use the re.IGNORECASE flag to make the regex case-insensitive
@app.route('/dns/<fqdn>', methods=['GET'])
def dnsapi(fqdn):
    validfqdn = re.fullmatch('^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$', fqdn, flags=re.IGNORECASE)
    if validfqdn:
        addr = socket.gethostbyname(fqdn)
        return {
            "hostname": fqdn,
            "addr": addr,
        }
    else:
        return render_template('404.html', title='404'), 404


# this page will display the result of the dns lookup
@app.route('/result', methods=['GET'])
def result():
    addr = request.args.get('addr')
    hostname = request.args.get('hostname')
    return render_template('result.html', title='result', addr=addr, hostname=hostname)
