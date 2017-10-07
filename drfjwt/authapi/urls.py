from django.conf.urls import url, include
from rest_framework_jwt.views import obtain_jwt_token
from authapi import views



urlpatterns = [

    #Below are function based Apis
    url(r'^createusers/$', views.new_user, name='new_user'),
    url(r'^jwt/$', obtain_jwt_token, name='obtain_jwt_token'),#used inbuilt function
    #url(r'^refereshtoken/$', obtain_jwt_token, name='obtain_jwt_token'),# can be used in future
    url(r'^login/$', views.login, name='login'),#custome login functionality
    url(r'^customjwt/$', views.create_jwt, name='create_jwt'),# custome JWT creation
    url('^', include('social_django.urls', namespace='social')),
    url(r'^socialsites/$', views.social_sites_login, name='social_sites_login'),
    url(r'^complete/google-oauth2/#', views.google, name='google'),

    # below are class based Apis
    url(r'^createuser/$', views.CreateUser.as_view()),
    url(r'^loginuser/$', views.LoginUser.as_view()),
    url(r'^createjwt/$', views.CreateJWT.as_view()),
    url(r'^logoutuser/$', views.LogoutUser.as_view()),
    url(r'^resetpassword/$', views.ResetPassword.as_view()),
    #url(r'^forgotpassword/$', views.ForgotPassword.as_view()),
    #url(r'^forgotpassword/$', views.ForgotPassword.as_view()),
    #url(r'^link/$', views.link, name='link')

]

# TODO:remove url comments, once use case is confirmed.
# TODO:remove any one of the apis(function based or class based), once use csae confirmed.
