import socket
import re
from app import app
from app.forms import Aform, PTRform, Emailform
from flask import render_template, flash, request, Markup, redirect


# these are the regex values we use to validate the input
fqdnregex = '^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$'
ptrregex = '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
emailregex = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

socket.timeout(5)


# this is our main page, nothing fancy here
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html.old', title='welcome to dnsTools!')


# this is for a typical A record lookup
# we use a regular expression to validate the input and throw an error for any situation like an NXDOMAIN
@app.route('/a', methods=['GET', 'POST'])
def dns():
    form = Aform()
    if request.method == 'POST' and form.validate():
        fqdn = form.hostname.data
        validfqdn = re.fullmatch(fqdnregex, fqdn, flags=re.ASCII | re.IGNORECASE)
        if validfqdn:
            try:
                addr = socket.gethostbyname(form.hostname.data)
                flash(Markup('dns lookup requested for domain name or FQDN {}'.format(
                    form.hostname.data) + ': the result is ' + addr), 'success')
            except socket.gaierror:
                flash(Markup('error in backend lookup, please notify the administrator'), 'danger')
            return redirect('/a')
        else:
            flash(Markup('invalid domain name or FQDN {} requested'.format(
                form.hostname.data)), 'danger')
            return redirect('/a')
    return render_template('dns.html', title='dns lookup', form=form)


# this is a PTR record lookup
# we use a regular expression to validate the input and throw an error
# we use the fullmatch method to ensure that the entire string matches the regex
# and the re.ASCII flag to make sure no wonky characters are entered, like unicode
@app.route('/ptr', methods=['GET', 'POST'])
def ptr():
    form = PTRform()
    if request.method == 'POST' and form.validate():
        validptr = re.fullmatch(ptrregex, form.ptr.data, flags=re.ASCII)
        if validptr:
            try:
                ptrresult = socket.gethostbyaddr(form.ptr.data)
                flash(Markup('ptr lookup requested for IP {}.'.format(
                    form.ptr.data) + ' the result is ' + str(ptrresult[0])) + '.', 'success')
            except socket.gaierror:
                flash(Markup('error in backend lookup, please notify the administrator'), 'danger')
            return redirect('/ptr')
        else:
            flash(Markup('invalid IP {} requested'.format(
                form.ptr.data)), 'danger')
            return redirect('/ptr')
    return render_template('dns.html', title='ptr lookup', form=form)


# this route will accept an email address and perform a validation on it, then check it for
# validity.
@app.route('/email', methods=['GET', 'POST'])
def email():
    form = Emailform()
    if request.method == 'POST' and form.validate():
        vemail = re.fullmatch(emailregex, form.email.data, flags=re.ASCII)
        if vemail:
            cemail = form.email.data
            flash('the email address ' + cemail + ' is valid', 'success')
        return redirect('/email')
    return render_template('dns.html', title='email validation', form=form)


# this page will display the result of the dns lookup
@app.route('/result', methods=['GET'])
def result():
    addr = request.args.get('addr')
    hostname = request.args.get('hostname')
    return render_template('result.html', title='result', addr=addr, hostname=hostname)
