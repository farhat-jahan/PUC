
'''
}}}}}}r4equest keys=}}}}} dict_keys(['twitter_state', 'twitterunauthorized_token_name', '_auth_user_id', '_auth_user_backend', '_auth_user_hash', 'social_auth_last_login_backend'])
kley is: twitter_state    and value is l6VZVqHGrN0mYKZzffRtC1hESfSehH5P
kley is: twitterunauthorized_token_name    and value is []
kley is: _auth_user_id    and value is 49
kley is: _auth_user_backend    and value is social_core.backends.twitter.TwitterOAuth
kley is: _auth_user_hash    and value is 04aab2de805fa102451cec05b8c149cb588c913a
kley is: social_auth_last_login_backend    and value is twitter
<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>
req.user========== AnonymousUser

exception us======??????????// User matching query does not exist.
puc                 : ERROR    JWT generation failed for the user:, exception-401



IN CASE OF GOOGLE SITE LOGIN
}}}}}}r4equest keys=}}}}} dict_keys(['google-oauth2_state', '_auth_user_id', '_auth_user_backend', '_auth_user_hash', 'social_auth_last_login_backend'])
kley is: google-oauth2_state    and value is JLnJAX3dsFgwsLmUDBdoied9sF1oL0GC
kley is: _auth_user_id    and value is 50
kley is: _auth_user_backend    and value is social_core.backends.google.GoogleOAuth2
kley is: _auth_user_hash    and value is 90e79eb9d8b68fd93606c97a858a4380ce50c532
kley is: social_auth_last_login_backend    and value is google-oauth2
<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>
req.user========== farhat.jahan
farhat.jahan
user=== farhat.jahan
puc                 : INFO     JWT is sent to registered user:farhat.jahan
[17/Oct/2017 16:58:56] "GET /api/successloginsocialsites HTTP/1.1" 200 7284

'''


'''

{'_request': <WSGIRequest: GET '/api/successloginsocialsites'>, 'parsers': [<rest_framework.parsers.JSONParser object at 0x105583da0>, 
<rest_framework.parsers.FormParser object at 0x105583e80>,<rest_framework.parsers.MultiPartParser object at 0x105583fd0>], 
 'authenticators': [<rest_framework_jwt.authentication.JSONWebTokenAuthentication object at 0x1055834e0>, <rest_framework.authentication.BasicAuthentication object at 0x1055833c8>,
  <rest_framework.authentication.SessionAuthentication object at 0x105583a58>], 
  'negotiator': <rest_framework.negotiation.DefaultContentNegotiation object at 0x1055834a8>,
   'parser_context': {'view': <authapi.views.SuccessLoginFromSocialSites object at 0x105583780>, 
   'args': (), 'kwargs': {}, 'request': <rest_framework.request.Request object at 0x1055835f8>, 
   'encoding': 'utf-8'}, '_data': <class 'rest_framework.request.Empty'>, 
   '_files': <class 'rest_framework.request.Empty'>, '_full_data': <class 'rest_framework.request.Empty'>, 

   '_content_type': <class 'rest_framework.request.Empty'>, '_stream': <class 'rest_framework.request.Empty'>,
    'accepted_renderer': <rest_framework.renderers.BrowsableAPIRenderer object at 0x1055835c0>, 
    'accepted_media_type': 'text/html', 'version': None, 'versioning_scheme': None, '_authenticator': None, 
    '_user': <django.contrib.auth.models.AnonymousUser object at 0x105583048>, '_auth': None}
<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>
'''

'''
{'_request': <WSGIRequest: GET '/api/successloginsocialsites'>, 'parsers': [<rest_framework.parsers.JSONParser object at 0x10fb0c0f0>, 
<rest_framework.parsers.FormParser object at 0x10fb0ce48>, <rest_framework.parsers.MultiPartParser object at 0x10fb0cc50>],
 'authenticators': [<rest_framework_jwt.authentication.JSONWebTokenAuthentication object at 0x10fb0c128>, <rest_framework.authentication.BasicAuthentication object at 0x10fb0cd68>, 
 <rest_framework.authentication.SessionAuthentication object at 0x10fb24438>], 
 'negotiator': <rest_framework.negotiation.DefaultContentNegotiation object at 0x10fb0cb70>, 
 'parser_context': {'view': <authapi.views.SuccessLoginFromSocialSites object at 0x10fadbe48>, 
 'args': (), 'kwargs': {}, 'request': <rest_framework.request.Request object at 0x10fb24ac8>, 'encoding': 'utf-8'}, 
 '_data': <class 'rest_framework.request.Empty'>,  
 '_files': <class 'rest_framework.request.Empty'>, '_full_data': <class 'rest_framework.request.Empty'>, 

 '_content_type': <class 'rest_framework.request.Empty'>, '_stream': <class 'rest_framework.request.Empty'>, 
 'accepted_renderer': <rest_framework.renderers.BrowsableAPIRenderer object at 0x10fb24240>,
  'accepted_media_type': 'text/html','version': None, 'versioning_scheme': None, 'csrf_processing_done': True, 
  '_authenticator': <rest_framework.authentication.SessionAuthentication object at 0x10fb24438>, 
'_user': <SimpleLazyObject: <User: farhat.jahand824652ae59f4996>>, '_auth': None}
'''

print("req is====", request)
print("+=======end================")
print("requ keys=====", request.session.keys())
print("+=======end================")
print("requ .session.values=====", request.session.values())
print("+=======end================")