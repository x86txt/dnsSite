import os


class Config(object):

    # look for an environment variable and if one is not found, use the generated string as a backup
    # note: this is for development only, remove for production!
    random_secret_key = os.urandom(64)
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or random_secret_key

    # here are the two vars required to configure our flask-bootstrap theme
    BOOTSTRAP_BOOTSWATCH_THEME = 'darkly'
    BOOTSTRAP_BTN_STYLE = 'secondary'

    # fix bugs with pyCharm not finding static files properly
    # see: https://intellij-support.jetbrains.com/hc/en-us/community/posts/360010553240/comments/360002880079
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
