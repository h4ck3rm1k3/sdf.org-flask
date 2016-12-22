#!/usr/pkg/bin/python
import os
print ("Content-Type: text/html\n\r\n\r")
print ("""<html><body><h2>Hello World! from python</h2><pre""")
for k,v in os.environ.items():
    print ("""{0} {1}""" .format(k,v) )
print ("""</pre></body></html>""")

       #n['SERVER_NAME']
# from wsgiref.handlers import CGIHandler
# from hello import app

# CGIHandler().run(app)
