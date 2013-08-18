import base64
import os
import os.path
import urllib
import hmac
import json
import hashlib
from base64 import urlsafe_b64decode, urlsafe_b64encode

import requests
from flask import Flask, request, session, redirect, render_template, url_for
import psycopg2
import psycopg2.extras
import urlparse

from Crypto.Cipher import AES
from Crypto import Random


class fb_api:
	def __init__(self):
		self.FB_APP_ID = os.environ.get('FACEBOOK_APP_ID')
		self.requests = requests.session()
		self.app_url = 'https://graph.facebook.com/{0}'.format(self.FB_APP_ID)
		self.FB_APP_NAME = json.loads(requests.get(self.app_url).content).get('name')
		self.FB_APP_SECRET = os.environ.get('FACEBOOK_SECRET')
		self.FBNS=os.environ.get('FBNS')
		self.app_secret_key =  hashlib.sha256(self.FB_APP_SECRET).digest()
		
		
	def get_tokens(self):
		if session.has_key('fbtiv'):
			fbtiv=base64.urlsafe_b64decode(session['fbtiv'])
		else:
			fbtiv = Random.new().read(AES.block_size)
			session['fbtiv']=base64.urlsafe_b64encode(fbtiv)
		cipher = AES.new(self.app_secret_key, AES.MODE_CFB, fbtiv)
		# get app access token
		try:
			app_access_token=self.app_access_token
		except AttributeError:
			app_access_token=self.get_application_access_token(self.FB_APP_ID)
			self.app_access_token=app_access_token
		#
		# get long lived user access token
		#
		try:
			long_uat=self.user_access_token
		except:
			has_uat=False
			if session.has_key('long_uat'):
				has_uat=True
				try:
			  		tmp_long_uat=cipher.decrypt(base64.urlsafe_b64decode(session['long_uat']))
				except:
					print 'exception in decrypt/decode'
					has_uat=False
			if has_uat and (self.is_valid(app_access_token,tmp_long_uat)):
				long_uat=tmp_long_uat
			else:
				access_token = self.get_token()
				# try twice ?
				if not access_token:
					access_token = self.get_token()
				if not access_token or not self.is_valid(app_access_token,access_token):
					print 'no access token'
					return False	
				long_uat=slef.extend_token(access_token)
				if not self.is_valid(app_access_token,long_uat):
					return False
				else:
					fbtiv = Random.new().read(AES.block_size)
					cipher = AES.new(self.app_secret_key, AES.MODE_CFB, fbtiv)
					session['fbtiv']=base64.urlsafe_b64encode(fbtiv)
					session['long_uat']=base64.urlsafe_b64encode(cipher.encrypt(long_uat))
					self.user_access_token=long_uat
				#
		return {'app_access_token':app_access_token,'user_access_token':long_uat}
		
			
    

	def extend_token(self,access_token):
			#params = {'grant_type':'fb_exchange_token',           
			# 'client_id':FB_APP_ID,
			# 'client_secret':FB_APP_SECRET,
			# 'fb_exchange_token':access_token} 
			if type(access_token)==list:
				access_token=access_token[0]
			new_token=requests.get('https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id='+str(FB_APP_ID)+'&client_secret='+FB_APP_SECRET+'&fb_exchange_token='+access_token)
			new_token=new_token.content
			pairs = new_token.split("&", 1)
			result_dict = {}
			for pair in pairs:
		  		(key, value) = pair.split("=")
		  		result_dict[key] = value
			new_token=result_dict['access_token']
			return new_token

	def is_valid(self,app_access_token,input_token):
			dbg = self.call('debug_token', args={'access_token': app_access_token,'input_token':input_token})
			#print 'is_valid:'
			#print dbg
			if dbg.has_key('data') and dbg['data'].has_key('is_valid'):
				return dbg['data']['is_valid']
			else:
				return False
	
	def oauth_login_url(self,preserve_path=True, next_url=None):
	    fb_login_uri = ("https://www.facebook.com/dialog/oauth"
	                    "?client_id=%s&redirect_uri=%s" %
	                    (app.config['FB_APP_ID'], get_home()))
	
	    if app.config['FBAPI_SCOPE']:
	        fb_login_uri += "&scope=%s" % ",".join(app.config['FBAPI_SCOPE'])
	    return fb_login_uri

	def simple_dict_serialisation(self,params):
	    return "&".join(map(lambda k: "%s=%s" % (k, params[k]), params.keys()))
    
	def base64_url_encode(self,data):
	    return base64.urlsafe_b64encode(data).rstrip('=')
 
	def fbapi_get_string(self,path,
	    domain=u'graph', params=None, access_token=None,
	    encode_func=urllib.urlencode):
	    """Make an API call"""

	    if not params:
	        params = {}
	    params[u'method'] = u'GET'
	    if access_token:
	        params[u'access_token'] = access_token

	    for k, v in params.iteritems():
	        if hasattr(v, 'encode'):
	            params[k] = v.encode('utf-8')

	    url = u'https://' + domain + u'.facebook.com' + path
	    params_encoded = encode_func(params)
	    url = url + params_encoded
	    result = requests.get(url).content

	    return result
 
	def fbapi_auth(self,code):
	    params = {'client_id': app.config['FB_APP_ID'],
	              'redirect_uri': get_home(),
	              'client_secret': app.config['FB_APP_SECRET'],
	              'code': code}

	    result = self.fbapi_get_string(path=u"/oauth/access_token?", params=params,
	                              encode_func=simple_dict_serialisation)
	    pairs = result.split("&", 1)
	    result_dict = {}
	    for pair in pairs:
	        (key, value) = pair.split("=")
	        result_dict[key] = value
	    return (result_dict["access_token"], result_dict["expires"])
	
	def get_application_access_token(self,id):
	 token=requests.get('https://graph.facebook.com/oauth/access_token?grant_type=client_credentials&client_id='+id+'&client_secret='+FB_APP_SECRET)
	 token=token.content
	 token=token.split('=')[-1]
    #token = fbapi_get_string(
    #    path=u"/oauth/access_token",
    #    params=dict(grant_type=u'client_credentials', client_id=id,
    #                client_secret=app.config['FB_APP_SECRET'],redirect_uri='none'),
    #    domain=u'graph')
    #token = token.split('=')[-1]
	 if not str(id) in token:
	     print 'Token mismatch: %s not in %s' % (id, token)
	 return token
	def fql(self,fql, token, args=None):
	    if not args:
	        args = {}

	    args["query"], args["format"], args["access_token"] = fql, "json", token

	    url = "https://api.facebook.com/method/fql.query"

	    r = requests.get(url, params=args)
	    return json.loads(r.content)

	def call(self,call, args=None):
	    url = "https://graph.facebook.com/{0}".format(call)
	    r = requests.get(url, params=args)
	    return json.loads(r.content)
	    
	def get_token(self):

	    if request.args.get('code', None):
	        return fbapi_auth(request.args.get('code'))[0]

	    cookie_key = 'fbsr_{0}'.format(FB_APP_ID)

	    if cookie_key in request.cookies:

	        c = request.cookies.get(cookie_key)
	        encoded_data = c.split('.', 2)

	        sig = encoded_data[0]
	        data = json.loads(urlsafe_b64decode(str(encoded_data[1]) +
	            (64-len(encoded_data[1])%64)*"="))

	        if not data['algorithm'].upper() == 'HMAC-SHA256':
	            raise ValueError('unknown algorithm {0}'.format(data['algorithm']))

	        h = hmac.new(FB_APP_SECRET, digestmod=hashlib.sha256)
	        h.update(encoded_data[1])
	        expected_sig = urlsafe_b64encode(h.digest()).replace('=', '')

	        if sig != expected_sig:
	            raise ValueError('bad signature')

	        code =  data['code']

	        params = {
	            'client_id': FB_APP_ID,
	            'client_secret': FB_APP_SECRET,
	            'redirect_uri': '',
	            'code': data['code']
	        }

	        from urlparse import parse_qs
	        r = requests.get('https://graph.facebook.com/oauth/access_token', params=params)
	        token = parse_qs(r.content).get('access_token')
	        return token

