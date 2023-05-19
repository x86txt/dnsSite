import os


class Config(object):
    # look for an environment variable and if one is not found, use the hardcoded string as a backup
    # note: this is for development only, remove for production!
    SECRET_KEY = os.environ.get('SECRET_KEY') or '5EMa4Zs7RR#gr@89kNVp2A7oKm7MgcYw!j2*Ywd'
    BOOTSTRAP_BOOTSWATCH_THEME = 'sandstone'
    BOOTSTRAP_BTN_STYLE = 'secondary'

    # fix bugs with pyCharm not finding static files properly
    # see: https://intellij-support.jetbrains.com/hc/en-us/community/posts/360010553240/comments/360002880079
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


