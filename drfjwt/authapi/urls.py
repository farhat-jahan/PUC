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

    # below are class based Apis
    url(r'^createuser/$', views.CreateUser.as_view(), name='creat_user'),
    url(r'^loginuser/$', views.LoginUser.as_view(), name='login_user'),
    url(r'^createjwt/$', views.CreateJWT.as_view(), name='create_jwt'),
    url(r'^logoutuser/$', views.LogoutUser.as_view(), name='logout_user'),
    url(r'^resetpassword/$', views.ResetPassword.as_view(), name='reset_password'),
    url(r'^forgotpasswordlink/$', views.ForgotPasswordlink.as_view(), name='forgot_password_link'),
    #url(r'^resetpasswdthroughlink/(?P<email_in>[\w@.]+)/(?P<token>\w+)/$', views.ResetPasswdThroughLink.as_view(), name='reset_password_through_link'),
    url(r'^resetpasswdthroughlink/', views.ResetPasswdThroughLink.as_view(), name='reset_password_through_link'),


    # Below is the setup for social_django (UI session based)
    url('^loginindex/', views.login_index, name='login_index'),
    url('^', include('social_django.urls', namespace='social')),
    url(r'^successloginsocialsites', views.SuccessLoginFromSocialSites.as_view(), name='successlogin_fromsocial_site'),



    # Below is the setup for rest_social_auth (JWT based), Api based
    # fixme:not implemented, if required do the implementation.
    # url(r'^', include('rest_social_auth.urls_jwt')),
    # url(r'^successloginsocialsitesjwt', views.successLoginFromsocialSiteJwt.as_view(), name='successlogin_fromsocial_site_jwt'),

    # TODO:Do forgot password implementation
    #url(r'^forgotpassword/$', views.ForgotPassword.as_view())
]

# TODO:remove url comments, once use case is confirmed.
# TODO:remove any one of the apis(function based or class based), once use csae confirmed.
