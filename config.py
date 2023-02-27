import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    # SECRET_KEY = os.environ.get('SECRET_KEY', None)
    #SECRET_KEY = ""
    DEBUG = True
    ACCESS_KEY = "4441f34a-a7c4-40a9-8d12-daf67d5727cd"
    SECRET_KEY = "oL4G1e7s14FmBFcaxAnLMmsq7SEGlHPqxuhJZBqaOUY="

    # Supported types with rules
    CCT_OBSERVABLE_TYPES = {
        'hostname': {},
        'device': {}
    }

    CTIM_DEFAULTS = {
        'schema_version': '1.0.22',
    }