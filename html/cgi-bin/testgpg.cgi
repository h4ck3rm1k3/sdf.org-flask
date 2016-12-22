#!/usr/pkg/bin/python
#-*- coding: utf-8 -*-

import sys
libbase='/www/gm/h/h4ck3rm1k3/lib/'
sys.path.append(libbase)
sys.path.append(libbase+'foursquare-master')
sys.path.append(libbase+'pyGPG-master')
sys.path.append(libbase+'flask-session-master/build/lib')

from datetime import timedelta

import pyGPG
from pyGPG.config import GPGConfig;
from pyGPG.gpg import GPG;

from time import gmtime, strftime
from werkzeug.debug import DebuggedApplication
from wsgiref.handlers import CGIHandler
import base64
import logging
import os
import pprint
import urllib

c=GPGConfig();
#c.set_key('gpg_command','/usr/pkg/bin/gpg')
DEBUG=True
keyid='e1af1d937ed92e18'
#keyid =  request.args.get('keyid')
astr = pprint.pformat({
    'keyid': keyid
    #         'environ' :request.environ,
    #         'form' :request.form,
    #         'headers' :request.headers,
    #         'data' :request.data,
    #         'session' : session.__dict__,
    #         'sesskeys': session.keys(),
    }, depth=5)
c=GPGConfig();
FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger=logging.getLogger()
logger.setLevel(logging.DEBUG)


g=GPG(c,logger)
logger.debug(astr)

g.encrypt(astr,keyid)
