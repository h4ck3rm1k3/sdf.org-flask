#!/usr/pkg/bin/python
<<<<<<< HEAD
import os
#REQUEST_URI -> /cgi-bin/hello2.cgi?q=fsdfsfds
#REQUEST_METHOD -> GET
#QUERY_STRING -> q=fsdfsfds
if 'REQUEST_URI' in os.environ:
    if 'SCRIPT_NAME' in os.environ:
        os.environ['REQUEST_URI']= os.environ['SCRIPT_NAME'] + "/" + os.environ['REQUEST_URI']
 
f = open ('/tmp/mike.txt','w')


from time import gmtime, strftime
nowt=strftime("%Y-%m-%d %H:%M:%S", gmtime())
f.write("Hello Flask:" + nowt +"\n") 
for k,v in os.environ.items():
    f.write ("""{0} {1}\n""" .format(k,v) )
f.close()
=======
#-*- coding: utf-8 -*-

import sys
libbase='/www/gm/h/h4ck3rm1k3/lib/'
sys.path.append(libbase)
sys.path.append(libbase+'foursquare-master')
sys.path.append(libbase+'pyGPG-master')
sys.path.append(libbase+'flask-session-master/build/lib')
from flask_session import Session
from flask import Flask, session
from flask import Response
from flask import make_response, request, current_app
from flask import request
from flask import url_for

from Crypto.Cipher import AES
from Crypto.Util import Counter
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
#c.set_key('gpg_command','/usr/pkg/bin/gpg')
DEBUG=True

if 'REQUEST_URI' in os.environ:
    if 'SCRIPT_NAME' in os.environ:
        os.environ['REQUEST_URI']= os.environ['SCRIPT_NAME'] + "/" + os.environ['REQUEST_URI']
#f = open ('logs/mike.txt','w')
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

>>>>>>> abe0a46... update

if 'REDIRECT_STATUS' in os.environ:
    del os.environ['REDIRECT_STATUS']
if 'REDIRECT_URL' in os.environ:
    del os.environ['REDIRECT_URL']

<<<<<<< HEAD


from flask import Flask
from wsgiref.handlers import CGIHandler
import cgitb;
cgitb.enable()  # This line enables CGI error reporting
import traceback

app = Flask(__name__)

from flask import request
from flask import url_for


from flask import Response
import pprint
=======
cgitb.enable()  # This line enables CGI error reporting

app = Flask(__name__)
app.debug = True
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

app.config['SECRET_KEY'] = 'super secret key DyWok7Wraysk@3'
def debug():
    assert app.debug == False, "Don't panic! You're here by request of debug()"



def error_report(error):
    f= open ('logs/mike.txt')
    l2 = f.readlines()
    f.close()
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb = u"\n".join(traceback.format_tb(exc_traceback))
    return "500 error <h1>%s</h1><pre>%s</pre> <pre>%s</pre>" % (error , tb, "\n".join(l2))
>>>>>>> abe0a46... update

@app.route("/test")
def test():
        str = pprint.pformat(request.environ, depth=5)
        return Response(str, mimetype="text/text")

<<<<<<< HEAD
import urllib
=======
@app.route("/test2")
def test2():
        str = pprint.pformat(request.environ, depth=5)
        return Response(str, mimetype="text/html")

@app.route("/gpg/postkey", methods=['POST'])
@crossdomain(origin='*',    methods=['POST'])
def gpg_postkey():
    data = {}
    sid = session.sid

    data['sid']=sid

    pubkey = "None"
    keyid="none"
    keyfinger="none"

    if 'user_pubkey' not in session:
        if 'pubkey' in request.form:
            pubkey=session['user_pubkey']=request.form['pubkey']
            keyid=session['keyid']=request.form['keyid']
            keyfinger=session['keyfinger']=request.form['keyfinger']
            session.permanent = True
        else:
            data['nopubkey']='yes'
    else:
        #session['user_pubkey']
        sid = session.sid
        #filename="keys/%s.pub" % sid
        pubkey=session['user_pubkey']
        keyid=session['keyid']
        keyfinger=session['keyfinger']
        data['hassession']='yes'
        
    filename="keys/%s.pub" % keyfinger
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
        'form keyfinger' :request.form['keyfinger'],
        'form' :request.form,
        'headers' :request.headers,
        'data' :request.data,
        'session pubkey' : session['user_pubkey'],
        'session' : session.__dict__,
        'session_keys' : session.keys(),

    }, depth=5)

    logger.debug("debug %s" % str)
    return Response("Key:%s" % str, mimetype="text/html")

# @app.route("/gpg/postkey2", methods=['GET'])
# def gpg_postkey2():
#     session['user_pubkey']="test"
#     str = pprint.pformat({
#         'environ' :request.environ,
#         'form' :request.form['pubkey'],
#         'headers' :request.headers,
#         'data' :request.data,
#         'pubkey' : session['user_pubkey'],
#         'session' : session.__dict__,
#     }, depth=5)
#     return Response("Key:%s" % str, mimetype="text/html")

@app.route("/gpg/secrets")
@crossdomain(origin='*')
def gpg_secrets():
    keyid =  request.args.get('keyid')
    astr = pprint.pformat({
        'keyid': keyid
    #         'environ' :request.environ,
    #         'form' :request.form,
    #         'headers' :request.headers,
    #         'data' :request.data,
    #         'session' : session.__dict__,
    #         'sesskeys': session.keys(),
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




# @app.route("/secrets/<iv>")
# def getsecrets(iv):
#     access_token=session['foursquare_access']
#     session.permanent = True
#     ctr = Counter.new(128, initial_value=long(iv.encode('hex'), 16))
#     cipher = AES.new(secret_key,AES.MODE_CTR, counter=ctr)

#     data =  {
#         'foursquare': { 'access_token': access_token },
#         #'all' : session.__dict__
#     }
#     str = pprint.pformat(data, depth=5)
#     encoded = base64.b64encode(cipher.encrypt(str))
#     return Response(encoded, mimetype="text/html")


@app.route("/foursquare/users/<user_id>")
def foursquare_users(user_id):
    access_token=session['foursquare_access']
    session.permanent = True
    client = foursquare.Foursquare(access_token=access_token)
    #https://foursquare.com/user/USER_ID
    data =client.users(user_id)
    str = pprint.pformat(data, depth=5)
    return Response(str, mimetype="text/html")



@app.route("/foursquare/oauth/authorize")
def foursquare_oauth_authorize():

    try :
        red = url_for('foursquare_oauth_authorize', _external=True)

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
        session.permanent = True
        str = """{0} access code {1}""".format(code, access_token)
        return Response(str, mimetype="text/html")

    except Exception as e:
        return Response(error_report(e), mimetype="text/html")

@app.route("/foursquare")
def foursquare_main():

    try :

        # Construct the client object

        red = url_for('foursquare_oauth_authorize', _external=True)

        foursquare_client = foursquare.Foursquare(
            client_id=secrets.foursquare_client_id,
            client_secret=secrets.foursquare_client_secret,
            redirect_uri= red
        )

        # Build the authorization url for your app
        auth_url = foursquare_client.oauth.auth_url()
        astr = """
        <a href='{0}'>auth callback</a>
        <a href='{1}'>auth url</a>
        """.format(red, auth_url)

        return Response(astr, mimetype="text/html")
    except Exception as e:
        return Response(error_report(e), mimetype="text/html")


>>>>>>> abe0a46... update

def list_routes():
    o = ""
    output = []
    for rule in app.url_map.iter_rules():
        options = {}
        for arg in rule.arguments:
            options[arg] = "[{0}]".format(arg)
<<<<<<< HEAD
            
=======

>>>>>>> abe0a46... update
        methods = ','.join(rule.methods)
        url = url_for(rule.endpoint, **options)
        line = urllib.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, url))
        output.append(line)

        for line in sorted(output):
            o=o+ "ROUTE" +line + "\n"
    return o

<<<<<<< HEAD
=======
@app.errorhandler(500)
def internal_error(error):
    f= open ('logs/mike.txt')
    l2 = f.readlines()
    f.close()

    return "500 error <h1>%s</h1> <pre>%s</pre>" % (error , "\n".join(l2))

>>>>>>> abe0a46... update
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
<<<<<<< HEAD
    
=======

>>>>>>> abe0a46... update

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

<<<<<<< HEAD
# class ScriptNameStripper(object):
#     def __init__(self, app):
#         self.app = app
#     def __call__(self, environ, start_response):
#         environ['SCRIPT_NAME'] = ''
#         return self.app(environ, start_response)

# app = ScriptNameStripper(app)
from werkzeug.debug import DebuggedApplication                                   
=======
>>>>>>> abe0a46... update

CGIHandler().run(DebuggedApplication(app))
