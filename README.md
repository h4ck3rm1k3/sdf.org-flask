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


# Support for oauth, example with foursquare :

1. start the process (static/file url)
https://github.com/h4ck3rm1k3/extractr/blob/master/templates/foursquare.html

1.2. this sends the call to the server 
https://github.com/h4ck3rm1k3/sdf.org-flask/blob/encrypt/html/cgi-bin/helloflask.cgi#L323

1.2.1 that then calls:
auth_url = foursquare_client.oauth.auth_url()
to get 
https://foursquare.com/oauth2/authenticate?redirect_uri=http%3A%2F%2Fh4ck3rm1k3.sdf.org%2Fcgi-bin%2Fhelloflask.cgi%2Ffoursquare%2Foauth%2Fauthorize%2F<sid>&response_type=code&client_id=<clientid>

where <sid> contains the sid to write the data to and <clientid> identifies the app. Note, this is one security issue that users could overwrite someone elses token if you know thier sid, but the cannot get access to yours.

We can add in some extra client identification here, or have the javascript manage the calling of the foursquare via js, need to look into that more.

see #session-locking

1.2.2 The user clicks on this url and authenticates with foursquare and is sent back to :
http://h4ck3rm1k3.sdf.org/cgi-bin/helloflask.cgi/foursquare/oauth/authorize/<sid>

1.2.3 This enters into /foursquare/oauth/authorize/<sid> 
https://github.com/h4ck3rm1k3/sdf.org-flask/blob/encrypt/html/cgi-bin/helloflask.cgi#L293
where the access token is read out and put into the users session.

2. the user then can read the access token from the server (static/file url) via gpg encrypted data.
https://github.com/h4ck3rm1k3/extractr/blob/master/templates/gpg_read.html

#Session Locking

## Problem :
The problem with using oauth over http is associating the session of the orginator with that of the callback from the user.
The originator is in file: domainless html page, the callback is redirected to the server and will get a new session/cookie. We pass the sid in the callback url and overwrite it, but this can be spoofed.

## Solution idea :
We should not allow this callback to modify the session data until the user can send a signed request to confirm the action.

## Proposal (not implemented yet)

1. The client could initiate a gpg signed request using the public key with :
/server/create-session
The session would return the session key encrypted.

2. The client would then be associated with that gpg key, ip address and generated session.

3. Insecure operations that follow are limited to the ip address.

The session token that is transmitted would be locked into the ip address and only that ip would be allowed to post. 
In a natted environment an inside attacker could then still spoof the data, but it wont be commited until picked up.

If there are more than one response pending (spoofing) the entire operation will be cancelled. Buffer size is basically one per client on the server.

4. The client will get the authentication token in the redirect url and then maybe transmit it to the server via gpg, or just keep it client sided.

5. The client will then unlock the session and optionally commit the data on the server with a gpg request. This will release the lock.
