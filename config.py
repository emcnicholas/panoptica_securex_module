import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)
    DEBUG = True
    ACCESSKEY = "4441f34a-a7c4-40a9-8d12-daf67d5727cd"
    SECRETKEY = "oL4G1e7s14FmBFcaxAnLMmsq7SEGlHPqxuhJZBqaOUY="