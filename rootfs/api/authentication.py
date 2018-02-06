from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User
import jwt
import requests
from rest_framework import authentication
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

class AnonymousAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone!
        """
        return AnonymousUser(), None


class AnonymousOrAuthenticatedAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request for anyone or if a valid token is provided, a user.
        """
        try:
            return TokenAuthentication.authenticate(TokenAuthentication(), request)
        except:
            return AnonymousUser(), None

class PlatformAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        """
        Authenticate the request if a valid token is provided, a user.
        """
        try:
            token = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            validate_token_request = requests.get(
                    settings.API_URL + '/v2/users/token/validate',
                    headers={ 'Authorization': 'Bearer ' + token })
            if validate_token_request.status_code != 200:
                raise Exception()
            user_mongo_id = jwt.decode(token, verify=False)['user']
            user_details_request = requests.get(
                    settings.API_URL + '/v2/users/' + user_mongo_id,
                    headers={ 'Authorization': 'Bearer ' + token })
            user_details = user_details_request.json()
            user = User.objects.get_or_create(
                    username=user_details['email'],
                    email=user_details['email'])
            return (user[0], None)
        except Exception as e:
            raise AuthenticationFailed()
