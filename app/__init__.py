from flask import Flask
from app.config import Config
from flask_cors import CORS
from flask_wtf import CSRFProtect
from flask_bootstrap import Bootstrap5  # https://github.com/helloflask/bootstrap-flask
import os

# create our application object (app) as an instance of the Flask class, from the flask package
# app = Flask(__name__,
#            static_url_path='',
#            static_folder='app/static',
#            template_folder='app/templates'
#            )
app = Flask(__name__)
CORS(app)

# import our config.py values, c = config.py, C = Config class
app.config.from_object(Config)

# we can handle CDN ourselves, so we serve the files locally from here
# todo: temporary disabled, need to figure out how to get this to work
app.config['BOOTSTRAP_SERVE_LOCAL'] = False

# let's take the key from the env var first and if that doesn't exist, generate one ourselves
secret_key = os.urandom(64)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secret_key

# workaround for circular imports, ignore ide lint error
# note: this one imports from the app declaration above, not the folder app which is the package name
from app.templates.old import routes
from app import apiroutes
from app import security

# initialize our bootstrap and csrf objects
bootstrap = Bootstrap5(app)
csrf = CSRFProtect(app)

# this is the main entry point for the application
if __name__ == '__main__':
    app.run(debug=False)
