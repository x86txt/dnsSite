from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators


class InputForm(FlaskForm):
    hostname = StringField('enter domain name or FQDN',
                           validators=[validators.DataRequired(message='please enter a domain name'),
                                       validators.InputRequired(message='please enter a domain name'),
                                       validators.Regexp('^(?!-)[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}$', message='please enter a valid domain name'),
                                       validators.length(max=255, message='domain name must be less than 255 characters')])
    submit = SubmitField('lookup')
