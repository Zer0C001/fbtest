# -*- coding: utf-8 -*-

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
import urlparse

from Crypto.Cipher import AES
from Crypto import Random


FB_APP_ID = os.environ.get('FACEBOOK_APP_ID')
requests = requests.session()

app_url = 'https://graph.facebook.com/{0}'.format(FB_APP_ID)
FB_APP_NAME = json.loads(requests.get(app_url).content).get('name')
FB_APP_SECRET = os.environ.get('FACEBOOK_SECRET')
FBNS=os.environ.get('FBNS')
app_secret_key =  hashlib.sha256(FB_APP_SECRET).digest()



def get_tokens(fbtiv=False,short_uat=False):
	if fbtiv or session.has_key('fbtiv'):
		if not fbtiv:
			fbtiv=session['fbtiv']
		cipher = AES.new(app_secret_key, AES.MODE_CFB, fbtiv)
		# get app access token
		if session.has_key('app_access_token'):
			app_access_token=cipher.decrypt(session['app_access_token'])
		else:
			app_access_token=fbapi_get_application_access_token(FB_APP_ID)
			session['app_access_token']=cipher.encrypt(app_access_token)
		#
		# get long lived user access token
		#
		has_uac=False
		if session.has_key('long_uac'):
			  tmp_long_uac=cipher.decrypt(session['long_uac'])
			  has_uac=True
		if has_uac and (is_valid(app_access_token,tmp_long_uac)):
			long_uac=tmp_long_uac
		else:
			if short_uat:
				access_token=short_uat
			else:
				access_token = get_token()
				# try twice ?
				if not access_token:
					access_token = get_token()
			if not access_token or not is_valid(app_access_token,access_token):
				return False	
			long_uac=fb_extend_token(access_token)
			#
		return {'app_access_token':app_access_token,'user_access_token':long_uac}
	else:
		fbtiv = Random.new().read(AES.block_size)
		session['fbtiv']=fbtiv
		return get_tokens(fbtiv,short_uat)
			
    

def fb_extend_token(access_token):
	#params = {'grant_type':'fb_exchange_token',           
   # 'client_id':FB_APP_ID,
   # 'client_secret':FB_APP_SECRET,
   # 'fb_exchange_token':access_token} 
	new_token=requests.get('https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id='+str(FB_APP_ID)+'&client_secret='+FB_APP_SECRET+'&fb_exchange_token='+access_token)
   #pairs = result.split("&", 1)
   #result_dict = {}
   #for pair in pairs:
   #     (key, value) = pair.split("=")
   #     result_dict[key] = value
	print 'extended token:'
	print new_token
	return new_token

def is_valid(app_access_token,input_token):
	dbg = fb_call('debug_token', args={'access_token': app_access_token,'input_token':input_token})
	print dbg
	return dbg['data']['is_valid']



def oauth_login_url(preserve_path=True, next_url=None):
    fb_login_uri = ("https://www.facebook.com/dialog/oauth"
                    "?client_id=%s&redirect_uri=%s" %
                    (app.config['FB_APP_ID'], get_home()))

    if app.config['FBAPI_SCOPE']:
        fb_login_uri += "&scope=%s" % ",".join(app.config['FBAPI_SCOPE'])
    return fb_login_uri


def simple_dict_serialisation(params):
    return "&".join(map(lambda k: "%s=%s" % (k, params[k]), params.keys()))


def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')


def fbapi_get_string(path,
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


def fbapi_auth(code):
    params = {'client_id': app.config['FB_APP_ID'],
              'redirect_uri': get_home(),
              'client_secret': app.config['FB_APP_SECRET'],
              'code': code}

    result = fbapi_get_string(path=u"/oauth/access_token?", params=params,
                              encode_func=simple_dict_serialisation)
    pairs = result.split("&", 1)
    result_dict = {}
    for pair in pairs:
        (key, value) = pair.split("=")
        result_dict[key] = value
    return (result_dict["access_token"], result_dict["expires"])


def fbapi_get_application_access_token(id):
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

def fql(fql, token, args=None):
    if not args:
        args = {}

    args["query"], args["format"], args["access_token"] = fql, "json", token

    url = "https://api.facebook.com/method/fql.query"

    r = requests.get(url, params=args)
    return json.loads(r.content)


def fb_call(call, args=None):
    url = "https://graph.facebook.com/{0}".format(call)
    r = requests.get(url, params=args)
    return json.loads(r.content)



app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_object('conf.Config')
app.secret_key=app_secret_key

def get_home():
    return 'https://' + request.host + '/'


def get_token():

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
        print str(r)+str(r.content)
        return token


@app.route('/', methods=['GET', 'POST'])
def index():
    # print get_home()


    access_token = get_token()
    # try twice ?
    if not access_token:
    	access_token = get_token()
    tokens=get_tokens(short_uat=access_token)
    print tokens

    channel_url = url_for('get_channel', _external=True)
    channel_url = channel_url.replace('http:', '').replace('https:', '')

    if access_token:

        me = fb_call('me', args={'access_token': access_token})
        fb_app = fb_call(FB_APP_ID, args={'access_token': access_token})
        likes =  fb_call('me/likes',
                        args={'access_token': access_token, 'limit': 4})

        redir = get_home() + 'close/'
        url = request.url
        
        app_access_token=fbapi_get_application_access_token(FB_APP_ID)
        	
        categories=fb_call('app/objects/'+FBNS+':category',args={'access_token': app_access_token})
        num_cat=len(categories['data'])
        content=''
        if num_cat==0:
        	init_cat=fb_call('app/objects/'+FBNS+':category',args={'access_token': app_access_token,'method':'POST', 'object': "{'title':'Uncategorized'}"})
        	#content+='   '+str(init_cat)
        suggestions=fb_call('app/objects/'+FBNS+':suggestion',args={'access_token': app_access_token,'fields':'id,created_time,data'})#,pos_votes,neg_votes,category_id'})
        sort=request.args.get('sort','votes')
        if suggestions.has_key('data'):
        	suggestions=suggestions['data']
        	for i in range(0,len(suggestions)):
        		if not suggestions[i].has_key('data'):
        		  del suggestions[i]
        	if sort=='date':
        		suggestions.sort(key=lambda k: k['created_time'])
        		suggestions.reverse()
        	elif sort=='votes':
        		suggestions.sort(key=lambda k: k['data']['pos_votes']+k['data']['neg_votes'])
        #	suggestions=l_obj
        disp_suggestions=[]
        for i in range(0,min(10,len(suggestions))):
	  disp_sug=fb_call(suggestions[i]['id'],args={'access_token': app_access_token})
	  disp_suggestions+=[disp_sug]
	  dbg=''+str(request.args)+str(request.form)+str(request.cookies)
	content=''#+str(disp_suggestions)+str(request.args)#+' '+str(request.form)+str(request.cookies)
        return render_template(
            'index.html', app_id=FB_APP_ID, token=access_token, app=fb_app,
            me=me, url=url,
            channel_url=channel_url, name=FB_APP_NAME+' '+FBNS+'  2',suggestions=disp_suggestions ,content=content,dbg=dbg)
    else:
        permission_list = ",".join(app.config['FBAPI_SCOPE']) 
        dbg=''+str(request.args)+str(request.form)+str(request.cookies)
        return render_template('login.html', app_id=FB_APP_ID, token=access_token, url=request.url, channel_url=channel_url, name=FB_APP_NAME,  permission_list=permission_list,dbg=dbg)

@app.route('/channel.html', methods=['GET', 'POST'])
def get_channel():
    return render_template('channel.html')


@app.route('/close/', methods=['GET', 'POST'])
def close():
    return render_template('close.html')



@app.route('/suggestion/new', methods=['GET', 'POST'])
def suggestion_new():
	if request.method=="GET":
	  access_token =  get_token()
	  if not access_token :
	    access_token =  get_token()
	  me = fb_call('me', args={'access_token': access_token})
	  return render_template('suggestion_new.html',me=me)
	elif request.method=="POST":
		#import datetime
		#datetimestr=str(datetime.datetime.now())
		access_token =  get_token()
		if not access_token :
			access_token =  get_token()
		app_access_token=fbapi_get_application_access_token(FB_APP_ID)
		me = fb_call('me', args={'access_token': access_token})
		channel_url = url_for('get_channel', _external=True)
		channel_url = channel_url.replace('http:', '').replace('https:', '') 
		content=request.form['content']
		if (not request.form.has_key('category_id')) or request.form['category_id']=='' or request.form['category_id']==None:
			categories=fb_call('app/objects/'+FBNS+':category',args={'access_token': app_access_token})
			if len(categories['data'])==1:
				category_id=categories['data'][0]['id']
		else:
			category_id=request.form['category_id']
		perm=fb_call('me/permissions',args={'access_token': access_token})
		me=fb_call('me',args={'access_token': access_token,'fields':'id'})
		# facebook object suggestion required fields ( og:title:'<the suggestion text>', creator_id:'<int:me.id>',pos_votes:<int>, neg_votes:<int>)
		if me.has_key('id'):
		  fbc=fb_call('app/objects/'+FBNS+':suggestion',args={'access_token': app_access_token,'method':'POST', 'object': "{'title':'"+content+"','data':{'creator_id':'"+str(me['id'])+"','pos_votes':'0','neg_votes':'0','category_id':'"+category_id+"','closed':'False'}}" })
		else:
			fbc={}
		#facebook object user_suggestion required fields ( og:title:'<empty string>', suggestion_id:<int> )
		if fbc.has_key('id'):
		  fbc1=fb_call('me/objects/'+FBNS+':user_suggestion',args={'access_token': access_token,'method':'POST', 'object': "{'title':'','data':{'suggestion_id':'"+fbc['id']+"'}}" })
		else:
			fbc1='error saving'

		dbg=Markup("save suggestion: <br>"+content+"<br>"+str(fbc)+"<br>"+str(fbc1)+'<br>user: '+str(me)+'<br>perms:<br>'+str(perm)+'<br><br>'+str(request.form)+str(access_token))
		return render_template('suggestion_saved.html',me=me,dbg=dbg,content='')
	
@app.route('/suggestion/<int:suggestion_id>', methods=['GET', 'POST'])
def suggestion_show(suggestion_id):
	access_token =  get_token()
	if not access_token :
		access_token =  get_token()
	me = fb_call('me', args={'access_token': access_token})
	app_access_token=fbapi_get_application_access_token(FB_APP_ID)
	suggestion=fb_call(str(suggestion_id),args={'access_token': app_access_token})
	return render_template('suggestion_show.html',me=me,content=str(suggestion)+str(request.form))



	
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    if app.config.get('FB_APP_ID') and app.config.get('FB_APP_SECRET'):
        app.run(host='0.0.0.0', port=port)
    else:
        print 'Cannot start application without Facebook App Id and Secret set'
