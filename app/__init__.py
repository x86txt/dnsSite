from flask import Flask
from config import Config
from flask_wtf import CSRFProtect
from flask_bootstrap import Bootstrap5  # https://github.com/helloflask/bootstrap-flask

# create our application object (app) as an instance of the Flask class, form the flask package
app = Flask(__name__)

# import our config.py values, c = config.py, C = Config class
app.config.from_object(Config)

# this is just temporary
app.secret_key = '7^7L@xd^q5LHt$AX9Eb$mL4sUem2!'

# workaround for circular imports, ignore ide lint error
# note: this one imports from the app declaration above, not the folder app which is the package name
from app import routes

bootstrap = Bootstrap5(app)
csrf = CSRFProtect(app)
