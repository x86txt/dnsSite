from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators


class Aform(FlaskForm):
    hostname = StringField('enter domain name or FQDN',
                           validators=[validators.DataRequired(message='please enter a domain name'),
                                       validators.InputRequired(message='please enter a domain name'),
                                       validators.Regexp('^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$', message='please enter a valid domain name'),
                                       validators.length(max=255, message='domain name must be less than 255 characters')])
    submit = SubmitField('lookup')


class PTRform(FlaskForm):
    ptr = StringField('enter an IPv4 address for PTR lookup',
                           validators=[validators.DataRequired(message='please enter an IPv4 address'),
                                       validators.InputRequired(message='please enter an IPv4 address'),
                                       validators.IPAddress(ipv4=True, message='please enter a valid IP address'),
                                       validators.length(max=255, message='domain name must be less than 255 characters')])
    submit = SubmitField('lookup')


# this class is for the email validation form
# we use the check deliverability flag to ensure that the email address is deliverable
class Emailform(FlaskForm):
    email = StringField('Enter an email address for validation',
                           validators=[validators.DataRequired(message='please enter an email address'),
                                       validators.InputRequired(message='please enter an email address'),
                                       validators.Email(message='please enter a valid email address', check_deliverability=True),
                                       validators.length(max=255, message='domain name must be less than 255 characters')])
    submit = SubmitField('lookup')
