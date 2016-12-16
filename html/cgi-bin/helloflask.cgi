#!/usr/pkg/bin/python
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

if 'REDIRECT_STATUS' in os.environ:
    del os.environ['REDIRECT_STATUS']
if 'REDIRECT_URL' in os.environ:
    del os.environ['REDIRECT_URL']



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

@app.route("/test")
def test():
        str = pprint.pformat(request.environ, depth=5)
        return Response(str, mimetype="text/text")

import urllib

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

# class ScriptNameStripper(object):
#     def __init__(self, app):
#         self.app = app
#     def __call__(self, environ, start_response):
#         environ['SCRIPT_NAME'] = ''
#         return self.app(environ, start_response)

# app = ScriptNameStripper(app)
from werkzeug.debug import DebuggedApplication                                   

CGIHandler().run(DebuggedApplication(app))
