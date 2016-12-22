#!/usr/pkg/bin/python
import os
import sys
import logging
logging.basicConfig(level=logging.DEBUG)

sys.path.append('/www/gm/h/h4ck3rm1k3/lib/')
sys.path.append(
                '/www/gm/h/h4ck3rm1k3/lib/foursquare-1!2016.9.12-py2-none-any.whl')
import foursquare
import secrets
import traceback
import pprint

red = "http://h4ck3rm1k3.sdf.org/cgi-bin/helloflask.cgi/foursquare/oauth/authorize"

foursquare_client = foursquare.Foursquare(
    client_id=secrets.foursquare_client_id,
    client_secret=secrets.foursquare_client_secret,
    redirect_uri= red
)

code='LWLKSW3IPLQVR22ZPCDLU52STIENCUU1HPH4C5KWKQ2TZCH1'
access_token = foursquare_client.oauth.get_token(code)
print "OK" + code + " access" + access_token
