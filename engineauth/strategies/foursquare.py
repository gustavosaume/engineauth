from __future__ import absolute_import
import json
from engineauth.models import User
from engineauth.strategies.oauth2 import OAuth2Strategy


class FoursquareStrategy(OAuth2Strategy):

    @property
    def options(self):
        return {
            'provider': 'foursquare',
            'site_uri': 'https://foursquare.com',
            'auth_uri': 'https://foursquare.com/oauth2/authenticate',
            'token_uri': 'https://foursquare.com/oauth2/access_token',
            }

    def user_info(self, req):
        url = "https://api.foursquare.com/v2/users/self?oauth_token=" + \
              req.credentials.access_token
        res, results = self.http(req).request(url)
        if res.status is not 200:
            return self.raise_error('There was an error contacting Foursquare. '
                                    'Please try again.')
        try:
            user = json.loads(results)['response']['user']
        except KeyError:
            return self.raise_error('There was an error contacting Foursquare. '
                                    'Please try again.')
                                    
        auth_id = User.generate_auth_id(req.provider, user['id'])
        return {
            'auth_id': auth_id,
            'info': {
                        'id': user['id'],
                        'displayName':("{0} {1}".format(user.get('firstName'), user.get('lastName', '')).strip()),
                        'name': {
                            'formatted':("{0} {1}".format(user.get('firstName'), user.get('lastName', '')).strip()),
                            'familyName': user.get('lastName'),
                            'givenName': user.get('firstName'),
        #                    'middleName': user.get('middle_name'),
        #                    'honorificPrefix': None,
        #                    'honorificSuffix': None,
                        },
        #                'birthday': user.get('birthday'), # user_birthday
                        'gender': user.get('gender'),
        #                'utcOffset': user.get('timezone'),
        #                'locale': user.get('locale'),
        #                'verified': user.get('verified'),
                        'emails': [
                                {
                                    'value': user['contact'].get('email') if 'contact' in user else None, # email
                                    'type': None, # home, work
                                    'primary': True # boolean
                                },
                        ],
                        'nickname':("{0} {1}".format(user.get('firstName'), user.get('lastName', '')).strip()),
                        'location': user.get('homeCity'), # user_location
        #                'aboutMe': user.get('bio'),
                        'image': {
                            'url': user.get('photo')                
                        },
        #                'urls': [],
                    },
            'extra': {
                    'raw_info': user,
            }
        }