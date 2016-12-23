#!/usr/pkg/bin/python
#-*- coding: utf-8 -*-

import sys
libbase='/www/gm/h/h4ck3rm1k3/lib/'
sys.path.append(libbase)
sys.path.append(libbase+'foursquare-master')
sys.path.append(libbase+'pyGPG-master')
sys.path.append(libbase+'flask-session-master') #/build/lib
from flask_session import Session
from flask import Flask, session
from flask import Response
from flask import make_response, request, current_app
from flask import request
from flask import url_for

from datetime import timedelta

from functools import update_wrapper

import pyGPG
from pyGPG.config import GPGConfig;
from pyGPG.gpg import GPG;

from time import gmtime, strftime
from werkzeug.debug import DebuggedApplication
from wsgiref.handlers import CGIHandler
import Crypto
import base64
import cgitb;
import foursquare
import httplib as http_client
import logging
import os
import pprint

import requests
import secrets
import traceback
import urllib

def crossdomain(origin=None, methods=None, headers=None,
                max_age=21600, attach_to_all=True,
                automatic_options=True):
    if methods is not None:
        methods = ', '.join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, basestring):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, basestring):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):


            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))

            resp.headers['skip']="mikewashere2"

            if not attach_to_all and request.method != 'OPTIONS':
                resp.headers['skip']="mikewashere"
                return resp

            h = resp.headers
            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            h['Access-Control-Allow-Credentials'] = 'true'
            h['Access-Control-Allow-Headers'] = \
                "Origin, X-Requested-With, Content-Type, Accept, Authorization"
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator

c=GPGConfig();
DEBUG=True

if 'REQUEST_URI' in os.environ:
    if 'SCRIPT_NAME' in os.environ:
        os.environ['REQUEST_URI']= os.environ['SCRIPT_NAME'] + "/" + os.environ['REQUEST_URI']
#f = open ('logs/mike2.txt','w')
http_client.HTTPConnection.debuglevel = 1
#nowt=strftime("%Y-%m-%d %H:%M:%S", gmtime())
#f.write("Hello Flask:" + nowt +"\n")
#f.close()
# You must initialize logging, otherwise you'll not see debug output.
#logging.basicConfig(filename="logs/mike2.txt",level=logging.DEBUG)
logger=logging.getLogger()
hdlr = logging.FileHandler('logs/mike2.txt')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

logger.warn("starting")
for k,v in os.environ.items():
    logger.debug ("""{0} {1}\n""" .format(k,v) )

requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


if 'REDIRECT_STATUS' in os.environ:
    del os.environ['REDIRECT_STATUS']
if 'REDIRECT_URL' in os.environ:
    del os.environ['REDIRECT_URL']

cgitb.enable()  # This line enables CGI error reporting

app = Flask(__name__)
app.debug = True
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

app.config['SECRET_KEY'] = 'super secret key DyWok7Wraysk@3'
def debug():
    assert app.debug == False, "Don't panic! You're here by request of debug()"



def error_report(error):
    f= open ('logs/mike2.txt')
    l2 = f.readlines()
    f.close()
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb = u"\n".join(traceback.format_tb(exc_traceback))
    return "500 error <h1>%s</h1><pre>%s</pre> <pre>%s</pre>" % (error , tb, "\n".join(l2))

@app.route("/test")
def test():
        str = pprint.pformat(request.environ, depth=5)
        return Response(str, mimetype="text/text")

@app.route("/test2")
def test2():
        str = pprint.pformat(request.environ, depth=5)
        return Response(str, mimetype="text/html")
    
@app.route("/gpg/testpostkey", methods=['POST'])
@crossdomain(origin='*',    methods=['POST'])
def gpg_testpostkey():
    sid = session.sid
    session.permanent = True
    session['sid1']=sid
    return Response("ok sid %s" % sid, mimetype="text/html")

@app.route("/gpg/postkey", methods=['POST'])
@crossdomain(origin='*',    methods=['POST'])
def gpg_postkey():
    #sid =  request.args.get('sid')
    #session.sid = sid
    data = {}
    #data['sid']=sid
    pubkey = "None"
    keyid="none"

    if 'user_pubkey' not in session:
        if 'pubkey' in request.form:
            pubkey=session['user_pubkey']=request.form['pubkey']
            keyid=session['keyid']=request.form['keyid']
#            keyfinger=session['keyfinger']=request.form['keyfinger']
#            session.permanent = True
        else:
            data['nopubkey']='yes'
            filename="keys/%s.pub" % "unknown"
    else:
        #session['user_pubkey']
        sid = session.sid
        #filename="keys/%s.pub" % sid
        pubkey=session['user_pubkey']
        keyid=session['keyid']
        #keyfinger=session['keyfinger']
        data['hassession']='yes'        
    filename="keys/%s.pub" % keyid
        
    data['filename']=filename
    g=GPG(c,logger)
    if not os.path.isfile(filename) :
        f= open( filename,'w')
        f.write(pubkey)
        f.close()
        s = os.stat(filename)
        s2=g.importkey(filename)
        data['list']=s2.output
        data['status']=s2.status.__dict__
        data['list2']=s2.__dict__
        logger.debug("File imported %s" % filename)
        data['filestat']=s
    else:
        s2= g.listkey()
        logger.debug("ret %s" % s2.output)
        logger.debug("File exists %s" % filename)
        data['list']=s2.output
        data['status']=s2.status.__dict__
        data['list2']=s2.__dict__

    data['end']='yes'

    str = pprint.pformat({
        'data1' : data,
        'environ' :request.environ,
        'form pubkey' :request.form['pubkey'],
        'form keyid' :request.form['keyid'],
        #'form keyfinger' :request.form['keyfinger'],
        'form' :request.form,
        'headers' :request.headers,
        'data' :request.data,
        'session pubkey' : session['user_pubkey'],
        'session' : session.__dict__,
        'session_keys' : session.keys(),

    }, depth=5)

    logger.debug("debug %s" % str)
    return Response("Key:%s" % str, mimetype="text/html")

@app.route("/session/get")
@crossdomain(origin='*')
def session_get():
    sid =session.sid
    return Response("%s" % sid, mimetype="text/html")
    
@app.route("/gpg/secrets")
@crossdomain(origin='*')
def gpg_secrets():
    #sid =  request.args.get('sid')
    #session.sid = sid

    data = {}
    for k in session.keys():
        v = session[k]
        data[k]=v
        
    keyid =  request.args.get('keyid')
    astr = pprint.pformat({
        'keyid': keyid,
        'session_data': data,
        'environ' :request.environ,
        'form' :request.form,
        'headers' :request.headers,
        'data' :request.data,
        'session' : session.__dict__,
        'sesskeys': session.keys(),
    }, depth=5)
    if keyid is not None:
        g=GPG(c,logger)
        o = g.encrypt(astr,keyid)
        astr = o.output
        return Response("%s" % astr, mimetype="text/html")
#     access_token=session['foursquare_access']
#     pubkey=session['user_pubkey']
#     data =  {
#         'pubkey': pubkey,
#         'foursquare': { 'access_token': access_token },
#     }
#     str = pprint.pformat(data, depth=5)
#     #encoded = base64.b64encode(cipher.encrypt(str))
#     encoded = str
#     return Response(encoded, mimetype="text/html")


@app.route("/foursquare/users/<user_id>")
@crossdomain(origin='*')
def foursquare_users(user_id):
    #sid =  request.args.get('sid')
    #session.sid = sid

    access_token=session['foursquare_access']
    session.permanent = True
    client = foursquare.Foursquare(access_token=access_token)
    #https://foursquare.com/user/USER_ID
    data =client.users(user_id)
    str = pprint.pformat(data, depth=5)
    return Response(str, mimetype="text/html")

@app.route("/foursquare/oauth/authorize/<sid>")
@crossdomain(origin='*')
def foursquare_oauth_authorize(sid):
    try :
        red = url_for('foursquare_oauth_authorize',sid=sid,  _external=True)

        foursquare_client = foursquare.Foursquare(
            client_id=secrets.foursquare_client_id,
            client_secret=secrets.foursquare_client_secret,
            redirect_uri= red
        )
        code =  request.args.get('code')
        #return "OK:" + code
        try:
            access_token = foursquare_client.oauth.get_token(code)
        except foursquare.FoursquareException as e:
            return Response(error_report(e), mimetype="text/html")
        except Exception as e:
            return Response(error_report(e), mimetype="text/html")

        #return "OK" + code + " access" + access_token
        session['foursquare_access'] = access_token
        session['foursquare_code'] = code
        session.permanent = True
        str = """{0} access code {1} red {2}""".format(code, access_token, red)
        return Response(str, mimetype="text/html")

    except Exception as e:
        return Response(error_report(e), mimetype="text/html")

@app.route("/foursquare")
@crossdomain(origin='*')
def foursquare_main():
    try :
        sid = session.sid
        # Construct the client object
        red = url_for('foursquare_oauth_authorize',sid=sid, _external=True)
        #+ "&sid=%s" % session.sid
        foursquare_client = foursquare.Foursquare(
            client_id=secrets.foursquare_client_id,
            client_secret=secrets.foursquare_client_secret,
            redirect_uri= red
        )
        # Build the authorization url for your app
        #auth_url = foursquare_client.oauth.auth_url_token()
        auth_url = foursquare_client.oauth.auth_url()
        session['foursquare_auth'] = auth_url
        session.permanent = True
        astr = """
        <a href='{0}'>auth callback</a>
        <a href='{1}'>auth url</a>
        """.format(red, auth_url)
        return Response(astr, mimetype="text/html")
    except Exception as e:
        return Response(error_report(e), mimetype="text/html")

def list_routes():
    o = ""
    output = []
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)

        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
        output.append(line)

        for line in sorted(output):
            o=o+ "ROUTE" +line + "\n"
    return o

@app.errorhandler(500)
def internal_error(error):
    f= open ('logs/mike2.txt')
    l2 = f.readlines()
    f.close()

    return "500 error <h1>%s</h1> <pre>%s</pre>" % (error , "\n".join(l2))

@app.errorhandler(404)
def page_not_found(e):
    pageName =  request.args.get('url')
    str = pprint.pformat(request.environ, depth=5)
    s = list_routes()
    return "Ooops  <pre>%s </pre>  <pre>%s </pre> <pre>%s</pre> <pre>%s</pre>" % (e, pageName, str, s), 200

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
        return 'You want path: %s' % path


@app.route('/')
def hello_world():
    return 'Hello, World2!'

@app.route('/hello')
@app.route('/hello/')
def hello_world2():
    return 'Hello, World3!'

@app.route('/foo/<anyt>')
def hello_world3(anyt):
    return 'Foo Hello, World3! %s' % anyt


CGIHandler().run(DebuggedApplication(app))
