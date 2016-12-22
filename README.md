# sdf.org-flask
Flask hosting on sdf.org, requires arpa lifetime membership.

see http://sdf.org/?tutorials/htaccess
http://sdf.org/?tutorials#web
http://sdf.org/?tutorials/building_a_website

# Semi-Serverless oauth webpage prototype using openpgp.js and pygpg.

This is an experiment to use gpg to replace https to share secrets with a client webpage that runs without being served from a server.

The client is a standalone html page that connects to a simple api hosted on sdf.org, with a lifetime membership you can run this server forever. 

The server will store your public key that you send to it, and the request oauth tokens on your behalf and send them back to you. 

Because static html pages without a server do not support cookies, we use local storage for your session data, and the session key is communicated in cleartext to the server. 
Any private data that could be acccessible will be gpg encrypted so even if someone knows your session id, they will not be able to read your data.

A modified version of the flask-sessions is used to get the SID not from a cookie but from the sid parameter passed.


## Uses server side sessions 

Using of Flask-session https://github.com/fengsp/flask-session forked to 
https://github.com/h4ck3rm1k3/flask-session/tree/stuff to support handling of sid in request args and form posts.


## Supports gpg encryption instead of https for secrects

Uses the pygpg module github.com/h4ck3rm1k3/pyGPG

0. Server has a local gpg setup that is writable to the http server.
0.1 Generate a private key

1. The client uses openpgp.js to generate a key

The client software can run in a html webpage without a server, it does not have a local cookie, so that it uses local storage for all persistence. 
This is a design goal that we use the remote server as a proxy for things that require a server and do the rest locally.

1.1 the client sets the password in local storage.
https://github.com/h4ck3rm1k3/extractr/blob/master/templates/set_password.html

2. Client generates a public key and posts it with an rpc call


https://github.com/h4ck3rm1k3/extractr/blob/master/templates/gpg.html

http://h4ck3rm1k3.sdf.org/a/gpg/postkey and the form variables pubkey and keyid.
The server takes the public key and adds it to a the local keystore.

3. The server encrypts data for the user with the call gpg/secrets?keyid={KeyID} 

The user passes the keyid in the call, and the data is encrypted with that keyid. The local keystore is used.

	gpg --armour --home ../gpghome -e -r {keyid} --trust-model always

4. The client uses openpgp.js to decrypt the output.

https://github.com/h4ck3rm1k3/extractr/blob/master/templates/gpg_read.html
https://github.com/openpgpjs/openpgpjs

