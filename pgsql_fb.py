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
	def __init__(self,session):
		self.session=session
		self.FB_APP_ID = os.environ.get('FACEBOOK_APP_ID')
		self.requests = requests.session()
		self.app_url = 'https://graph.facebook.com/{0}'.format(self.FB_APP_ID)
		self.FB_APP_NAME = json.loads(requests.get(self.app_url).content).get('name')
		self.FB_APP_SECRET = os.environ.get('FACEBOOK_SECRET')
		self.FBNS=os.environ.get('FBNS')
		self.app_secret_key =  hashlib.sha256(self.FB_APP_SECRET).digest()
		self.user_id=False
		
	def process_signed_request(self,form):
		if form.has_key('signed_request'):
			sr=form['signed_request']
			sr=sr.split('.')
			srq=json.loads(base64.b64decode(sr[1]+'=='))
			self.user_id=int(srq['user_id'])
			self.user_access_token=srq['oauth_token']			
			return srq
		
	def get_tokens(self):
		session=self.session
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
			#print 'no app_access_token in self'
			app_access_token=self.get_application_access_token(self.FB_APP_ID)
			self.app_access_token=app_access_token
		#
		# get long lived user access token
		#
		try:
			tmp_long_uat=self.user_access_token
			has_uat=True
		except:
			#print 'no user_access_token in self'
			has_uat=False
			if session.has_key('long_uat'):
				has_uat=True
				try:
			  		tmp_long_uat=cipher.decrypt(base64.urlsafe_b64decode(session['long_uat']))
				except:
					#print 'exception in decrypt/decode'
					has_uat=False
			#print 'line 62'
		if has_uat and (self.is_valid(app_access_token,tmp_long_uat)):
			long_uat=tmp_long_uat
			self.user_access_token=long_uat
			#print 'has uat'
		else:
			access_token = self.get_token()
			# try twice ?
			if not access_token:
				access_token = self.get_token()
			if not access_token or not self.is_valid(app_access_token,access_token):
				#print 'no access token'
				return False	
			long_uat=self.extend_token(access_token)
			#print 'line 76'
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
			new_token=requests.get('https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id='+str(self.FB_APP_ID)+'&client_secret='+self.FB_APP_SECRET+'&fb_exchange_token='+access_token)
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
			print 'is_valid:'
			print dbg
			print self.session
			if dbg.has_key('data') and dbg['data'].has_key('is_valid'):
				if self.user_id:
					print 'has uid'
					if self.user_id!=dbg['data']['user_id']:
						return False
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
	 token=requests.get('https://graph.facebook.com/oauth/access_token?grant_type=client_credentials&client_id='+id+'&client_secret='+self.FB_APP_SECRET)
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
	    print 'get short token'
	    
	    if request.args.get('code', None):
	        return fbapi_auth(request.args.get('code'))[0]

	    cookie_key = 'fbsr_{0}'.format(self.FB_APP_ID)

	    if cookie_key in request.cookies:

	        c = request.cookies.get(cookie_key)
	        encoded_data = c.split('.', 2)

	        sig = encoded_data[0]
	        data = json.loads(urlsafe_b64decode(str(encoded_data[1]) +
	            (64-len(encoded_data[1])%64)*"="))

	        if not data['algorithm'].upper() == 'HMAC-SHA256':
	            raise ValueError('unknown algorithm {0}'.format(data['algorithm']))

	        h = hmac.new(self.FB_APP_SECRET, digestmod=hashlib.sha256)
	        h.update(encoded_data[1])
	        expected_sig = urlsafe_b64encode(h.digest()).replace('=', '')

	        if sig != expected_sig:
	            raise ValueError('bad signature')

	        code =  data['code']

	        params = {
	            'client_id': self.FB_APP_ID,
	            'client_secret': self.FB_APP_SECRET,
	            'redirect_uri': '',
	            'code': data['code']
	        }

	        from urlparse import parse_qs
	        r = requests.get('https://graph.facebook.com/oauth/access_token', params=params)
	        token = parse_qs(r.content).get('access_token')
	        return token


class data_fb:
	def __init__(self,session):
		print 'init data_fb'
		self.fb=fb_api(session)
		self.login_finished=False
		
		
	def on_index(self,request):
		print str(self.fb.process_signed_request(request.form))
		
	def login(self):
		if not self.login_finished:
			print 'login'
			self.tokens=self.fb.get_tokens()
			self.login_finished=True		
		return self.tokens
		
	def me(self,strict=True):
		self.login()
		try:
			me=self.fb.call('me', args={'access_token': self.tokens['user_access_token']})
		except:
			me=False 
		if not strict:
			if type(me)==bool:
				me={}
			if not me.has_key('name'):
				me['name']=''
			if not me.has_key('id'):
				me['id']=0
		return me
		
	def get_fb_app(self):
		fb_app = self.fb.call(self.fb.FB_APP_ID, args={'access_token': self.fb.app_access_token})
		return fb_app
		
	def get_categories(self):
		categories=self.fb.call('app/objects/'+self.fb.FBNS+':category',args={'access_token': self.fb.app_access_token})
		num_cat=len(categories['data'])
		if num_cat==0:
		 	init_cat=self.fb.call('app/objects/'+self.fb.FBNS+':category',args={'access_token': self.fb.app_access_token,'method':'POST', 'object': "{'title':'Uncategorized'}"})
		 	categories=self.fb.call('app/objects/'+self.fb.FBNS+':category',args={'access_token': self.fb.app_access_token})
		return categories
		
	def get_suggestion(self,suggestion_id):
		return self.fb.call(suggestion_id,args={'access_token': self.fb.app_access_token})
		
		
class data_pgsql:
	def __init__(self,db_url):
		print 'init data_pgsql'
		self.db_url=db_url
	def new_suggestion(self,suggestion_id,creator_id,category_id):
		self.get_cursor()
		saved=False
		try:
			self.cur.execute("insert into suggestions(id,creator_id,category_id,created_time,pos_votes,neg_votes,closed) values ("+str(suggestion_id)+","+str(creator_id)+","+str(category_id)+",now(),0,0,false);")
			saved=True
		except:
			saved=False
		self.conn.close()
		return saved
	def get_cursor(self):
		try:
			self.conn = psycopg2.connect(self.db_url)
			self.conn.autocommit=True
			self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
		except:
			print 'error connecting'
		
		
class data_pgsql_fb(data_pgsql,data_fb):
	def __init__(self,db_url,session):
		print 'init data_pgsql_fb'
		data_pgsql.__init__(self,db_url)
		data_fb.__init__(self,session)
		raise NotImplementedError,"class not implemented yet"