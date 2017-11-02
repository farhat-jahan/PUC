from django.db import transaction
from django.shortcuts import redirect, render, render_to_response
from rest_framework.authentication import BaseAuthentication, SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import MethodNotAllowed
from rest_framework import status
from rest_framework_jwt.utils import jwt_payload_handler
from rest_framework_jwt.settings import api_settings
from django.contrib.auth import authenticate as auth_authenticate
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator

from authapi.puc_exceptions import PucValidationError
from authapi.serializers import UserProfileSerializer
from authapi.models import UserProfile
from drfjwt import settings
import jwt
import datetime
import sys
import logging

logger = logging.getLogger('puc')

@api_view(['POST'])
def new_user(request):
    """ registered the users, if user is not already registered and returns registered user.
    :param request:
    :return:registered user
    """
    parser = JSONParser().parse(request)
    try:
        user = User.objects.get(username=parser['username'])
    except:
        user = User.objects.create_user(username=parser['username'], password=parser['password'])
        user.save()
    user.first_name = parser['first_name']
    user.last_name = parser['last_name']
    user.save()
    serializer = UserProfileSerializer(data={'user':user.id, 'phone_number':parser['phone_number'], 'date_of_birth':parser['date_of_birth']})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
def login(request):
    """authorized the user and returns Json web token.
    :param request:
    :return:JWT
    """
    parser = JSONParser().parse(request)
    if parser['username'] and parser['password']:
        user = auth_authenticate(username=parser['username'], password=parser['password'])
        if user is not None:
            token = login_token(user)
            return JsonResponse(data=token, status=status.HTTP_200_OK)
        if user is None:
            return Response(data={'error':'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response(data={'error': 'password and username required'}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
def create_jwt(request):
    """ takes request param and returns Json web token.
    :param request:
    :return:JWT
    """
    parser = JSONParser().parse(request)
    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
    if parser['username'] and parser['password']:
        user = auth_authenticate(username=parser['username'], password=parser['password'])
        if user:
            payload = jwt_payload_handler(user)
        else:
            return Response(data={'error':'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response(data={'error':'password and username required'}, status=status.HTTP_400_BAD_REQUEST)
    token = jwt_encode_handler(payload)
    return Response(data={'token':token}, status=status.HTTP_200_OK)


#################################################   CLASS BASED API   ################################################################
#TODO:remove functions based Apis, once class based APIs are confirmed

# class CreateUser(APIView):
#     """ registered the user, if user is not already registered and returns registered user.
#     :param request:
#     :return:registered user
#     """
#     def get(self, request):
#         raise MethodNotAllowed('GET')
#
#     def post(self, request, format=None):
#         parser = JSONParser().parse(request)
#         if parser['username']:
#             try:
#                 user = User.objects.get(username=parser['username'])
#             except:
#                 #valid_email = validate_email(parser['email'])
#                 user = User.objects.create_user(username=parser['username'], password=parser['password'])
#                 logger.info("New auth user:{0} is created".format(user.username))
#                 user.save()
#             #valid_email = validate_email(parser['email'])
#
#             user.first_name = parser['first_name']
#             user.last_name = parser['last_name']
#             user.save()
#             serializer = UserProfileSerializer(data={'user': user.id, 'phone_number': parser['phone_number'],
#                                                      'date_of_birth': parser['date_of_birth']})
#             if serializer.is_valid():
#                 serializer.save()
#                 logger.info("New UserProfile is created with username:{0} and phone number:{1}".format(user.username, parser['phone_number']))
#                 return Response(serializer.data, status=status.HTTP_201_CREATED)
#             else:
#                 logger.error("Failed to registered user, exception-{0}".format(serializer.errors))
#                 return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CreateUser(APIView):
    """ registered the user, if user is not already registered and returns registered user.
    username, email, phone_number are unique
    :param request:
    :return:registered user
    """
    def get(self, request):
        raise MethodNotAllowed('GET')

    def post(self, request, format=None):
        parser = JSONParser().parse(request)

        with transaction.atomic():
            if parser['username']:
                try:
                    user = User.objects.get(username=parser['username'])
                except:
                    user = User.objects.create_user(username=parser['username'], password=parser['password'],email=parser['email'])
                    logger.info("New auth user:{0} is created".format(user.username))
                    user.save()
                user.first_name = parser['first_name']
                user.last_name = parser['last_name']
                user.save()
                serializer = UserProfileSerializer(data={'user': user.id, 'date_of_birth': parser['date_of_birth'],
                                                         'phone_number':parser['phone_number']})
                if serializer.is_valid():
                    serializer.save()
                    logger.info("New UserProfile is created with username:{0} and phone number:{1}".format(user.username, parser['phone_number']))

                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    logger.error("Failed to registered user, exception-{0}".format(serializer.errors))
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# def validate_phone(args):
#     phone_number = args.strip()
#     if len(phone_number)<10 or phone_number.isdigit()==False:
#         raise PucValidationError(message="Phone number must be entered in the format: '9999999999'. Up to 15 digits allowed.",
#                                  status=status.HTTP_400_BAD_REQUEST)
#     return phone_number


class LoginUser(APIView):
    """authorized the user and returns Json web token.
    :param request: request
    :return:JWT
    """
    def get(self, request, format=None):
        return MethodNotAllowed('GET')

    def post(self, request, format=None):
        parser = JSONParser().parse(request)
        if parser['username'] and parser['password']:
            user = auth_authenticate(username=parser['username'], password=parser['password'])
            if user is not None:
                token = login_token(user)
                logger.info("JWT is sent to registered user:{0}".format(parser['username']))
                return JsonResponse(data=token, status=status.HTTP_200_OK)
            if user is None:
                logger.error("JWT generation failed for the user:{0}, exception-{1}".format(parser['username'], status.HTTP_401_UNAUTHORIZED))
                return Response(data={'error': 'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(data={'error': 'password and username required'}, status=status.HTTP_400_BAD_REQUEST)


class CreateJWT(APIView):
    """ takes request param and returns Json web token.
    :param request:
    :return:JWT
    """
    def get(self, request, format=None):
        return MethodNotAllowed('GET')

    def post(self, request, format=None):
        parser = JSONParser().parse(request)
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        if parser['username'] and parser['password']:
            user = auth_authenticate(username=parser['username'], password=parser['password'])
            if user:
                payload = jwt_payload_handler(user)
            else:
                logger.error("JWT generation failed for the user:{0}, exception-{1}".format(parser['username'], {'error': 'unautorized user'}))
                return Response(data={'error': 'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response(data={'error': 'password and username required'}, status=status.HTTP_400_BAD_REQUEST)
        token = jwt_encode_handler(payload)
        logger.info("JWT is sent to registered user:{0}".format(parser['username']))
        return Response(data={'token': token}, status=status.HTTP_200_OK)

class LogoutUser(APIView):
    """
    takes JWT token, validates the JWT and redirect the user to Login URl.
    :param request: token
    :param format:None
    :return:
    """

    def get(self, request, format=None):
        return MethodNotAllowed('GET')


    def post(self, request, format=None):
        token = (request.META['HTTP_AUTHORIZATION']).split()[1]
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY)
                user = UserProfile.objects.get(user__username=payload['username'], user_id=payload['user_id'])
            except:
                return Response(data={'error': 'invalid authentication'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'message': 'Succesfully Loged out '})
            #fixme:this line- return redirect('login')-need to fix
            #return redirect('login')
        return Response({"Error":"Token is required"}, status=status.HTTP_400_BAD_REQUEST)

    # def post(self, request, format=None):
    #     return Response({'message':'Logout functionality need to implement UI/client side'})

def login_token(user):
    """ takes user and generates Json web token.
    :param user: userdata
    :return:JWT
    """
    api_settings.JWT_EXPIRATION_DELTA = datetime.timedelta(days=2)
    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
    payload = jwt_payload_handler(user)
    token = jwt_encode_handler(payload)
    return {'token': token}

class ResetPassword(APIView):
    """ Takes JWT and other param and reset the password
    :param
        request
        JWT,
        new_password,
        confirm_new_password
    :param format: Json
    :return: reset password success message
    """
    def get(self, request, format=None):
        return MethodNotAllowed('GET')

    def post(self, request, format=None):
        token = (request.META['HTTP_AUTHORIZATION']).split()[1]
        parser = JSONParser().parse(request)
        new_password = parser['new_password']
        confirm_new_password = parser['confirm_new_password']
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY)
            except Exception as e:
                return Response(data={'error':'error in decoding token'}, status=status.HTTP_400_BAD_REQUEST)
                logging.error('JsonWebTokenAuthentication. No Json web token found.'.format(e))
            try:
                user = User.objects.get(username=payload['username'])
            except ObjectDoesNotExist:
                return Response(data={'error': 'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
            if new_password != confirm_new_password:
                return Response(data={'error':'new_password does not matches the confirm_new_passwords'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user.set_password(str(new_password))
                user.save()
                userprofile = UserProfile.objects.get(user=user)
                userprofile.reset_password = True
                userprofile.reset_password_date = datetime.datetime.now()
                userprofile.save()
            except Exception as e:
                return Response(data={'error':'Exception while changing password, exception-{0}'.format(e)})

            return Response(data={'sucess':'Password updated'})

        else:
            return Response(data={'error':'token is required for this request'}, status=status.HTTP_400_BAD_REQUEST)

def login_index(request):
    return render(request,'login_index.html')

#from rest_framework.authentication import SessionAuthentication
# class CsrfExemptSessionAuthentication(SessionAuthentication):
#
#     def enforce_csrf(self, request):
#         return  # To not perform the csrf check previously happening


#authentication_classes = (, BasicAuthentication)
class SuccessLoginFromSocialSites(APIView):
    """ Logged in the user from social sites and uses sessions authentication , ex: Google, Facebook and returns Json web token.
    :param request:
    :param format:
    :return:JWT
    """

    def post(self, request, format=None):
        return MethodNotAllowed('POST')

    #authentication_classes = (BasicAuthentication,CsrfExemptSessionAuthentication)
    def get(self, request, format=None):
        try:
            user = User.objects.get(username=request.user.username)
        except Exception as e:
            logger.error("JWT generation failed for the user:{0}, exception-{1}".format(request.user.username,
                                                                                        status.HTTP_401_UNAUTHORIZED))
            return Response(data={'error': 'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
        token = login_token(user)
        logger.info("JWT is sent to registered user:{0}".format(request.user.username))
        return Response(data=token, status=status.HTTP_200_OK)


class successLoginFromsocialSiteJwt(APIView):
    pass

class ForgotPasswordlink(APIView):
    """ Takes Email and returns success message
        :param:email
        :return:success message
        """

    def get(self, request, format=None):
        return MethodNotAllowed('GET')

    def post(self, request, format=None):
        # send_mail(
        #     'Subject here',
        #     'Here is the message.',
        #     'from@example.com',
        #     ['to@example.com'],
        #     fail_silently=False,
        # )
        token = (request.META['HTTP_AUTHORIZATION']).split()[1]
        parser = JSONParser().parse(request)
        user_email = parser['email']
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY)
            except Exception as e:
                return Response(data={'error': 'error in decoding token'}, status=status.HTTP_400_BAD_REQUEST)
                logging.error('JsonWebTokenAuthentication. No Json web token found.'.format(e))
            try:
                user = User.objects.get(username=payload['username'], email=payload['email'])
            except ObjectDoesNotExist:
                return Response(data={'error': 'invalid authentication key'}, status=status.HTTP_401_UNAUTHORIZED)
            #random_token_forlink = "xxY67Ttgg56"
            random_token_forlink = default_token_generator.make_token(user)
            mail_content = " Please click on the URL %s to reset your password" #% (url)
            print("final mail content with url???????????", mail_content)
            try:
                send_mail('Markett : Reset Password Link', mail_content, settings.EMAIL_HOST_USER, ["farhat.jahan@powerupcloud.com"])
            except Exception as e:
                logger.error("email sending failed for the email {}".format(user_email))
            return Response(data={"message":"Mail has been sent successfully. Please check your inbox(or spam folder) and reset your password"},
                            status=status.HTTP_200_OK)

        else:
            return Response(data={'error': 'token is required for this request'}, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswdThroughLink(APIView):
    def post(self, request):
        default_token_generator.check_token(request.user, request.token)
        pass


# def generate_otp(request):
#     if request.method == 'POST':
#         try:
#             username = request.POST['username']
#             user = User.objects.get(username=username)
#             phone_number = ''
#             user_profile_obj = UserProfile.objects.filter(user=user)
#             if user_profile_obj:
#                 phone_number = user_profile_obj[0].phone_number
#             logger.info('OTP request received . username: {0}'.format(username))
#             token = otp_handler.get_otp(user=user)
#             message = message_template.get_template('SEND_OTP').format(token)
#             send_job_to_queue(send_otp, {'phone_number': phone_number, 'message': message,
#                                          'sms_client': settings.SMS_CLIENT})
#             logger.info('OTP sent to mobile {0}'.format(phone_number))
#             #             #Send email if email address exist
#             if user.email:
#                 sent_otp_email(data=token, receiver=user.email, subject='Forgot Password')
#
#             return HttpResponseRedirect('/aftersell/users/otp/validate?username=' + username)
#
#         except Exception as ex:
#             logger.error('Invalid details, mobile {0}'.format(phone_number))
#             return HttpResponseRedirect('/aftersell/users/otp/generate?details=invalid')
#
#     elif request.method == 'GET':
#         return render(request, 'portal/get_otp.html')


