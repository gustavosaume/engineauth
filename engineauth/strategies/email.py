"""
    engineauth.strategies.email
    ============================

    Email Authentication Strategy (send validation)
    Based on the work of kyle.finley@gmail.com (Kyle Finley)
    
    :copyright: (c) 2012 Gustavo Saume.
    :license: Apache Sotware License, see LICENSE for details.

    :copyright: (c) 2010 Google Inc.
    :license: Apache Software License, see LICENSE for details.
"""
from __future__ import absolute_import
from engineauth import models
from engineauth.strategies.base import BaseStrategy
import webapp2
from webapp2_extras import security
import uuid
import datetime, time

__author__ = 'gustavosaume@gmail.com (Gustavo Saume)'


class EmailStrategy(BaseStrategy):

    def user_info(self, req):
        email = req.POST['email']
        user_info = req.POST.get('user_info', {})
        user_info['emails'] = [{'value': email, 'type': 'home', 'primary': True}]
        user_info['email'] = email
        auth_id = models.User.generate_auth_id(req.provider, email)
        return {
            'auth_id': auth_id,
            'info': user_info,
            'extra': {
                'raw_info': user_info,
                }
        }

    def get_or_create_profile(self, auth_id, user_info, **kwargs):
        """
        Overrides to provide logic for checking and encrypting  passwords.
        :param auth_id:
        :param user_info:
        :param kwargs:
        :return:
        :raise:
        """
        password = kwargs.pop('password')
        profile = models.UserProfile.get_by_id(auth_id)
        if profile is None:
            # Create profile
            profile = models.UserProfile.get_or_create(auth_id, user_info,
                password=security.generate_password_hash(password, length=12),
                **kwargs)
        # Check password
        if not security.check_password_hash(password, profile.password):
            return self.raise_error('The password that you\'ve provided '
                                    'doesn\'t match our records. '
                                    'Please try again.')
        return profile

    def callback(self, req):
        token = req.GET['token']
        email = req.GET['email']
        timestamp = req.GET['ts']
        
        if not token or not email:
            self.raise_error('Invalid confirmation link, please validate.')
        
        auth_id = models.User.generate_auth_id(req.provider, email)
        profile = models.UserProfile.get_by_id(auth_id)
        
        if not profile:
            return self.raise_error('The information that you\'ve provided '
                                    'doesn\'t match our records. '
                                    'Please try again.')
        
        if not security.check_password_hash(profile.password+timestamp, token):
            return self.raise_error('The information that you\'ve provided '
                                    'doesn\'t match our records. '
                                    'Please try again.')
                                    
        delta_time = datetime.date.fromtimestamp(float(timestamp)) - datetime.date.today()
        if delta_time.days >= 1:
            return self.raise_error('Expired validation link. '
                                    'Please try again.')
            
                                    
        profile.verified = True
        profile.put()
        
        req.load_user_by_profile(profile)
        
        return req.get_redirect_uri()

    def start(self, req):
        # confirm that required fields are provided.
        password = req.POST['password']
        email = req.POST['email']
        
        if not password or not email:
            return self.raise_error('Please provide a valid email '
                                    'and a password.')
                                    
        user_info = self.user_info(req)
        profile = self.get_or_create_profile(
            auth_id=user_info['auth_id'],
            user_info=user_info,
            password=password,
            verified=False)
        
        # generate and save reset_token
        timestamp = str(time.time())
        token_value = security.generate_password_hash(profile.password+timestamp, length=12)
        
        if not profile.verified:
            self.callback_uri = '{0}{1}/{2}/callback?email={3}&ts={4}&token={5}'.format(req.host_url,
                self.config['base_uri'], req.provider, email, timestamp, token_value)
            
            # send confirmation email
            from google.appengine.api import mail
            
            mail.send_mail(sender="Example.com Support <support@example.com>",
                          to=email,
                          subject="Your account has been approved",
                          body="""
            Dear %(email)s:
            
            Your example.com account has been approved.  Please follow the link below to validate your account
            %(callback)s
            
            Please let us know if you have any questions.
            
            The example.com Team
            """%dict(email=email, callback=self.callback_uri))
            
            # show user validation process info
            req.add_message('Check your email')
        else:
            # the user has been validated and the password is OK
            req.load_user_by_profile(profile)
        return req.get_redirect_uri()

    def handle_request(self, req):
        if not req.provider_params:
            return self.start(req)
        else:
            return self.callback(req)