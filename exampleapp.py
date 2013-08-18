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
import psycopg2.extras
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
db_url=os.environ.get('DATABASE_URL')

import pgsql_fb



app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_object('conf.Config')
app.secret_key=app_secret_key

def get_home():
    return 'https://' + request.host + '/'




@app.route('/', methods=['GET', 'POST'])
def index():
	 # print get_home()
	fb=pgsql_fb.data_fb(session)
	tokens=fb.login()
	print tokens
	channel_url = url_for('get_channel', _external=True)
	channel_url = channel_url.replace('http:', '').replace('https:', '')

	me = fb.me(strict=False)
	fb_app = fb.fb.call(FB_APP_ID, args={'access_token': fb.fb.app_access_token})
	
	redir = get_home() + 'close/'
	url = request.url
	  
	  	
	categories=fb.fb.call('app/objects/'+FBNS+':category',args={'access_token': fb.fb.app_access_token})
	num_cat=len(categories['data'])
	content=''
	if num_cat==0:
	  	init_cat=fb.fb.call('app/objects/'+FBNS+':category',args={'access_token': fb.fb.app_access_token,'method':'POST', 'object': "{'title':'Uncategorized'}"})
	suggestions=fb.fb.call('app/objects/'+FBNS+':suggestion',args={'access_token': fb.fb.app_access_token,'fields':'id,created_time,data'})#,pos_votes,neg_votes,category_id'})
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
	  disp_sug=fb.fb.call(suggestions[i]['id'],args={'access_token': fb.fb.app_access_token})
	  disp_suggestions+=[disp_sug]
	content=''#+str(disp_suggestions)+str(request.args)#+' '+str(request.form)+str(request.cookies)
	permission_list = ",".join(app.config['FBAPI_SCOPE'])
	
	return render_template(
	      'index.html', app_id=FB_APP_ID, app=fb_app,
	      me=me, url=url,
	      channel_url=channel_url, name=FB_APP_NAME+' '+FBNS+'  2',suggestions=disp_suggestions ,content=content,permission_list=permission_list)


@app.route('/channel.html', methods=['GET', 'POST'])
def get_channel():
    return render_template('channel.html')


@app.route('/close/', methods=['GET', 'POST'])
def close():
    return render_template('close.html')



@app.route('/suggestion/new', methods=['GET', 'POST'])
def suggestion_new():
	fb=pgsql_fb.fb_api(session)
	if request.method=="GET":
	  tokens=fb.get_tokens()
	  if not tokens:
	  	return "Error please try again"
	  me = fb.call('me', args={'access_token': tokens['user_access_token']})
	  return render_template('suggestion_new.html',me=me)
	elif request.method=="POST":
		tokens=fb.get_tokens()
		if not tokens:
			return "Error please try again"
		me = fb.call('me', args={'access_token': tokens['user_access_token']})
		channel_url = url_for('get_channel', _external=True)
		channel_url = channel_url.replace('http:', '').replace('https:', '') 
		content=request.form['content']
		if (not request.form.has_key('category_id')) or request.form['category_id']=='' or request.form['category_id']==None:
			categories=fb.call('app/objects/'+FBNS+':category',args={'access_token': tokens['app_access_token']})
			if len(categories['data'])==1:
				category_id=categories['data'][0]['id']
		else:
			category_id=request.form['category_id']
		perm=fb.call('me/permissions',args={'access_token': tokens['user_access_token']})
		me=fb.call('me',args={'access_token': tokens['user_access_token'],'fields':'id'})
		# facebook object suggestion required fields ( og:title:'<the suggestion text>', creator_id:'<int:me.id>',pos_votes:<int>, neg_votes:<int>,closed:<bool>)
		if me.has_key('id'):
		  fbc=fb.call('app/objects/'+FBNS+':suggestion',args={'access_token': tokens['app_access_token'],'method':'POST', 'object': "{'title':'"+content+"','data':{'creator_id':'"+str(me['id'])+"','pos_votes':'0','neg_votes':'0','category_id':'"+category_id+"','closed':'False'}}" })
		else:
			fbc={}
		#facebook object user_suggestion required fields ( og:title:'<empty string>', suggestion_id:<int> )
		if fbc.has_key('id'):
		  fbc1=fb.call('me/objects/'+FBNS+':user_suggestion',args={'access_token': tokens['user_access_token'],'method':'POST', 'object': "{'title':'','data':{'suggestion_id':'"+fbc['id']+"'}}" })
		  
		  pg=pgsql_fb.data_pgsql(db_url)
		  pg0=pg.new_suggestion(suggestion_id=fbc['id'],creator_id=me['id'],category_id=category_id)
		  
		else:
			fbc1='error saving'
			pg0="fbc_err"
		dbg="save suggestion: <br>"+content+"<br>"+str(fbc)+"<br>"+str(fbc1)+'\n pg:'+str(pg0)+' <br>user: '+str(me)+'<br>perms:<br>'+str(perm)+'<br><br>'+str(request.form)
		return render_template('suggestion_saved.html',me=me,dbg=dbg,content='')
	
@app.route('/suggestion/<int:suggestion_id>', methods=['GET', 'POST'])
def suggestion_show(suggestion_id):
	fb=pgsql_fb.data_fb(session)
	tokens=fb.login()
	me = fb.me(strict=False)
	suggestion=fb.fb.call(str(suggestion_id),args={'access_token': fb.fb.app_access_token})
	return render_template('suggestion_show.html',me=me,content=str(suggestion)+str(request.form),suggestion_url=get_home()+'suggestion/'+str(suggestion_id))



	
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    if app.config.get('FB_APP_ID') and app.config.get('FB_APP_SECRET'):
        app.run(host='0.0.0.0', port=port)
    else:
        print 'Cannot start application without Facebook App Id and Secret set'
