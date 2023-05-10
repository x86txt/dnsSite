import os


class Config(object):
    # look for an environment variable and if one is not found, use the hardcoded string as a backup
    # note: this is for development only, remove for production!
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    BOOTSTRAP_BOOTSWATCH_THEME = 'sandstone'
    BOOTSTRAP_BTN_STYLE = 'secondary'
