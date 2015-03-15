# Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
# See full license at the bottom of this file.
# from urllib.parse import quote
import requests
import json
import base64
import logging
import uuid
import datetime
from requests_oauthlib import OAuth2Session


api_instance = None


def get_instance():
    global api_instance
    if api_instance is None:
        api_instance = OneDriveForBusinessAPI()
    return api_instance


class OneDriveAPIException(Exception):

    def __init__(self, args=None):
        super().__init__()
        if args is None:
            pass
        elif 'error_description' in args:
            self.errno = args['error']
            self.message = args['error_description']
        elif 'error' in args and 'code' in args['error']:
            args = args['error']
            self.errno = args['code']
            self.message = args['message']
        else:
            self.errno = 0
            self.message = ''

    def __str__(self):
        return self.message + ' (' + self.errno + ')'


class OneDriveAuthError(OneDriveAPIException):

    """
    Raised when authentication fails.
    """
    pass


class OneDriveServerInternalError(OneDriveAPIException):
    pass


class OneDriveValueError(OneDriveAPIException):

    """
    Raised when input to OneDriveAPI is invalid.
    """
    pass

class OneDriveForBusinessAPI:

    # The authorize URL format string
    authorize_base_url = 'https://login.windows.net/common/oauth2/authorize'

    # The token endpoint, where we send the auth code to get an access token
    access_token_url = 'https://login.windows.net/common/oauth2/token'

    # The discovery service resource and endpoint are constant
    discovery_resource = 'https://api.office.com/discovery/'
    discovery_endpoint = 'https://api.office.com/discovery/v1.0/me/services'

    # Client information
    client_secret = 'dIKqnN1mokqr3kDlBUO7q0MlCt3amcjNLqp6oYUzk+o='
    client_id = '6de641e6-aa0a-4481-b7c8-bb5dc984824d'
    client_redirect_uri = \
        'https://odfb.mwallaceauthzen.onmicrosoft.com/reply'

    authorize_url = None
    state = None

    auth_code = None

    _oSession = None

    # Used for debug logging
    logger = logging.getLogger(__name__)

    # Set to False to bypass SSL verification
    # Useful for capturing API calls in Fiddler
    verifySSL = True

    @property
    def oSession(self):
        if (self._oSession is None):
            self._oSession = \
                OAuth2Session(self.client_id,
                              redirect_uri=self.client_redirect_uri)
        return self._oSession

    def get_auth_uri(self):
        authorize_uri, state = self.oSession.authorization_url(
            self.authorize_base_url)
        return authorize_uri

    def get_access_token(self, callback_uri, resource_uri):
        return self.oSession.fetch_token(self.access_token_url,
                                         authorization_response=callback_uri,
                                         client_secret=self.client_secret,
                                         resource=resource_uri)

    def get_authcode(self):
        self.logger.debug('Entering get_authcode.')
        self.logger.debug('  authorize_url: {0}'.format(self.authorize_url))

        self.auth_codedebug('Sending request to authorization endpoint.')
        oauth_session = OAuth2Session(self.client_id)
        authorize_url, state = \
            oauth_session.authorization_url(self.authorize_base_url)

    # Once the app has obtained an authorization code, it will call this
    # function. The function will request an access token for the discovery
    # service, then call the discovery service to find resource IDs and
    # endpoints for all services the app has permssions for
    def get_access_info_from_authcode(self):
        self.logger.debug('Entering get_access_info_from_authcode.')
        self.logger.debug('  auth_code: {0}'.format(self.auth_code))
        self.logger.debug('  redirect_uri: {0}'.format(self.redirect_uri))

        self.logger.debug('Sending request to access token endpoint.')
        post_data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.redirect_uri,
            'resource': self.discovery_resource,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        r = requests.post(self.access_token_url, data=post_data,
                          verify=self.verifySSL)
        self.logger.debug('Received response from token endpoint.')
        self.logger.debug(r.json())

        # Get the discovery service access token and do discovery
        try:
            discovery_service_token = r.json()['access_token']
            self.logger.debug('Extracted access token from response: {0}'
                              .format(discovery_service_token))
        except:
            self.logger.debug('Exception encountered, setting token to None.')
            discovery_service_token = None

        if (discovery_service_token):
            # Add the refresh token to the dictionary to be returned
            # so that the app can use it to request additional access tokens
            # for other resources without having to re-prompt the user.
            discovery_result = self.do_discovery(discovery_service_token)
            self.logger.debug('Discovery completed.')
            discovery_result['refresh_token'] = r.json()['refresh_token']

            # Get the user's email from the access token and add to the
            # dictionary to be returned.
            json_token = self.parse_token(discovery_service_token)
            self.logger.debug('Discovery token after parsing: {0}'
                              .format(json_token))
            discovery_result['user_email'] = json_token['upn']
            self.logger.debug('Extracted email from token: {0}'
                              .format(json_token['upn']))
            self.logger.debug('Leaving get_access_info_from_authcode.')
            return discovery_result
        else:
            self.logger.debug('Leaving get_access_info_from_authcode.')
            return None

    # This function calls the discovery service and parses
    # the result. It builds a dictionary of resource IDs and API endpoints
    # from the results.
    def do_discovery(self, token):
        self.logger.debug('Entering do_discovery.')
        self.logger.debug('  token: {0}'.format(token))

        headers = {
            'Authorization': 'Bearer {0}'.format(token),
            'Accept': 'application/json'
        }
        r = requests.get(self.discovery_endpoint, headers=headers,
                         verify=self.verifySSL)

        discovery_result = {}

        for entry in r.json()['value']:
            capability = entry['capability']
            self.logger.debug('Capability found: {0}'.format(capability))
            discovery_result['{0}_resource_id'.format(capability)] = \
                entry['serviceResourceId']
            discovery_result['{0}_api_endpoint'.format(capability)] = \
                entry['serviceEndpointUri']
            self.logger.debug('  Resource ID: {0}'
                              .format(entry['serviceResourceId']))
            self.logger.debug('  API endpoint: {0}'
                              .format(entry['serviceEndpointUri']))

        self.logger.debug('Leaving do_discovery.')
        return discovery_result

    # Once the app has obtained access information (resource IDs and API
    # endpoints) it will call this function to get an access token for a
    # specific resource.
    def get_access_token_from_refresh_token(self, refresh_token, resource_id):
        self.logger.debug('Entering get_access_token_from_refresh_token.')
        self.logger.debug('  refresh_token: {0}'.format(refresh_token))
        self.logger.debug('  resource_id: {0}'.format(resource_id))

        post_data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
            'resource': resource_id
        }

        r = requests.post(self.access_token_url, data=post_data,
                          verify=self.verifySSL)

        self.logger.debug('Response: {0}'.format(r.json()))
        # Return the token as a JSON object
        self.logger.debug('Leaving get_access_token_from_refresh_token.')
        return r.json()

    # This function takes the base64-encoded token value and breaks
    # it into header and payload, base64-decodes the payload, then
    # loads that into a JSON object.
    def parse_token(self, encoded_token):
        self.logger.debug('Entering parse_token.')
        self.logger.debug('  encoded_token: {0}'.format(encoded_token))

        try:
            # First split the token into header and payload
            token_parts = encoded_token.split('.')

            # Header is token_parts[0]
            # Payload is token_parts[1]
            self.logger.debug('Token part to decode: {0}'
                              .format(token_parts[1]))

            decoded_token = self.decode_token_part(token_parts[1])
            self.logger.debug('Decoded token part: {0}'.format(decoded_token))
            self.logger.debug('Leaving parse_token.')
            return json.loads(decoded_token)
        except:
            return 'Invalid token value: {0}'.format(encoded_token)

    def decode_token_part(self, base64data):
        self.logger.debug('Entering decode_token_part.')
        self.logger.debug('  base64data: {0}'.format(base64data))

        # base64 strings should have a length divisible by 4
        # If this one doesn't, add the '=' padding to fix it
        leftovers = len(base64data) % 4
        self.logger.debug('String length % 4 = {0}'.format(leftovers))
        if leftovers == 2:
            base64data += '=='
        elif leftovers == 3:
            base64data += '='

        self.logger.debug('String with padding added: {0}'.format(base64data))
        decoded = base64.b64decode(base64data)
        self.logger.debug('Decoded string: {0}'.format(decoded))
        self.logger.debug('Leaving decode_token_part.')
        return decoded.decode('utf-8')

    # Generic API Sending
    def make_api_call(self, method, url, token, payload=None):
        # Send these headers with all API calls
        headers = {
            'User-Agent': 'pythoncontacts/1.2',
            'Authorization': 'Bearer {0}'.format(token),
            'Accept': 'application/json'
        }

        # Use these headers to instrument calls. Makes it easier
        # to correlate requests and responses in case of problems
        # and is a recommended best practice.
        request_id = str(uuid.uuid4())
        instrumentation = {
            'client-request-id': request_id,
            'return-client-request-id': 'true'
        }

        headers.update(instrumentation)

        response = None

        if (method.upper() == 'GET'):
            self.logger.debug('{0}: Sending request id: {1}'
                              .format(datetime.datetime.now(), request_id))
            response = requests.get(url, headers=headers, verify=self.verifySSL)
        elif (method.upper() == 'DELETE'):
            self.logger.debug('{0}: Sending request id: {1}'
                              .format(datetime.datetime.now(), request_id))
            response = requests.delete(url, headers=headers,
                                       verify=self.verifySSL)
        elif (method.upper() == 'PATCH'):
            headers.update({
                'Content-Type': 'application/json'
            })
            self.logger.debug('{0}: Sending request id: {1}'
                              .format(datetime.datetime.now(), request_id))
            response = requests.patch(url, headers=headers, data=payload,
                                      verify=self.verifySSL)
        elif (method.upper() == 'POST'):
            headers.update({
                'Content-Type': 'application/json'
            })
            self.logger.debug('{0}: Sending request id: {1}'
                              .format(datetime.datetime.now(), request_id))
            response = requests.post(url, headers=headers, data=payload,
                                     verify=self.verifySSL)

        if (response is not None):
            self.logger.debug(('{0}: Request id {1} completed. Server id: {2}, '
                               'Status: {3}')
                              .format(datetime.datetime.now(),
                                      request_id,
                                      headers.get('request-id'),
                                      response.status_code))

        return response


"""
    # Contacts API #

    # Retrieves a set of contacts from the user's default contacts folder
    #   parameters:
    #     contact_endpoint: string. The URL to the Contacts API endpoint
    #     token: string. The access token
    #     parameters: string. An optional string containing query parameters to
    #                 filter, sort, etc.
    def get_contacts(contact_endpoint, token, parameters = None):
        logger.debug('Entering get_contacts.')
        logger.debug('  contact_endpoint: {0}'.format(contact_endpoint))
        logger.debug('  token: {0}'.format(token))
        if (not parameters is None):
            logger.debug('  parameters: {0}'.format(parameters))

        get_contacts = '{0}/Me/Contacts'.format(contact_endpoint)

        if (not parameters is None):
            get_contacts = '{0}{1}'.format(get_contacts, parameters)

        r = make_api_call('GET', get_contacts, token)

        if (r.status_code == requests.codes.unauthorized):
            logger.debug('Leaving get_contacts.')
            return None

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving get_contacts.')
        return r.json()

    # Retrieves a single contact
    #   parameters:
    #     contact_endpoint: string. The URL to the Contacts API endpoint
    #     token: string. The access token
    #     contact_id: string. The ID of the contact to retrieve.
    #     parameters: string. An optional string containing query parameters to
    #                 limit the properties returned.
    def get_contact_by_id(contact_endpoint, token, contact_id, parameters=None):
        logger.debug('Entering get_contact_by_id.')
        logger.debug('  contact_endpoint: {0}'.format(contact_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  contact_id: {0}'.format(contact_id))
        if (not parameters is None):
            logger.debug('  parameters: {0}'.format(parameters))

        get_contact = '{0}/Me/Contacts/{1}'.format(contact_endpoint, contact_id)

        if (not parameters is None and
            parameters != ''):
            get_contact = '{0}{1}'.format(get_contact, parameters)

        r = make_api_call('GET', get_contact, token)

        if (r.status_code == requests.codes.ok):
            logger.debug('Response: {0}'.format(r.json()))
            logger.debug('Leaving get_contact_by_id(.')
            return r.json()
        else:
            logger.debug('Leaving get_contact_by_id.')
            return None

    # Deletes a single contact
    #   parameters:
    #     contact_endpoint: string. The URL to the Contacts API endpoint
    #     token: string. The access token
    #     contact_id: string. The ID of the contact to delete.
    def delete_contact(contact_endpoint, token, contact_id):
        logger.debug('Entering delete_contact.')
        logger.debug('  contact_endpoint: {0}'.format(contact_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  contact_id: {0}'.format(contact_id))

        delete_contact = '{0}/Me/Contacts/{1}'.format(contact_endpoint,
                                                      contact_id)

        r = make_api_call('DELETE', delete_contact, token)

        logger.debug('Leaving delete_contact.')

        return r.status_code

    # Updates a single contact
    #   parameters:
    #     contact_endpoint: string. The URL to the Contacts API endpoint
    #     token: string. The access token
    #     contact_id: string. The ID of the contact to update.
    #     update_payload: string. A JSON representation of the properties to
    #                     update.
    def update_contact(contact_endpoint, token, contact_id, update_payload):
        logger.debug('Entering update_contact.')
        logger.debug('  contact_endpoint: {0}'.format(contact_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  contact_id: {0}'.format(contact_id))
        logger.debug('  update_payload: {0}'.format(update_payload))

        update_contact = '{0}/Me/Contacts/{1}'.format(contact_endpoint,
                                                      contact_id)

        r = make_api_call('PATCH', update_contact, token, update_payload)

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving update_contact.')

        return r.status_code

    # Creates a contact
    #   parameters:
    #     contact_endpoint: string. The URL to the Contacts API endpoint
    #     token: string. The access token
    #     contact_payload: string. A JSON representation of the new contact.
    def create_contact(contact_endpoint, token, contact_payload):
        logger.debug('Entering create_contact.')
        logger.debug('  contact_endpoint: {0}'.format(contact_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  contact_payload: {0}'.format(contact_payload))

        create_contact = '{0}/Me/Contacts'.format(contact_endpoint)

        r = make_api_call('POST', create_contact, token, contact_payload)

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving create_contact.')

        return r.status_code

    # Mail API #

    # Retrieves a set of messages from the user's Inbox
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     parameters: string. An optional string containing query parameters to
                      filter, sort, etc.
    def get_messages(mail_endpoint, token, parameters=None):
        logger.debug('Entering get_messages.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        if (not parameters is None):
            logger.debug('  parameters: {0}'.format(parameters))

        get_messages = '{0}/Me/Messages'.format(mail_endpoint)

        if (not parameters is None):
            get_messages = '{0}{1}'.format(get_messages, parameters)

        r = make_api_call('GET', get_messages, token)

        if (r.status_code == requests.codes.unauthorized):
            logger.debug('Leaving get_messages.')
            return None

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving get_messages.')
        return r.json()

    # Retrieves a single message
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     message_id: string. The ID of the message to retrieve.
    #     parameters: string. An optional string containing query parameters to
    #                 limit the properties returned.
    def get_message_by_id(mail_endpoint, token, message_id, parameters=None):
        logger.debug('Entering get_message_by_id.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  message_id: {0}'.format(message_id))
        if (not parameters is None):
            logger.debug('  parameters: {0}'.format(parameters))

        get_message = '{0}/Me/Messages/{1}'.format(mail_endpoint, message_id)

        if (not parameters is None and
            parameters != ''):
            get_message = '{0}{1}'.format(get_message, parameters)

        r = make_api_call('GET', get_message, token)

        if (r.status_code == requests.codes.ok):
            logger.debug('Response: {0}'.format(r.json()))
            logger.debug('Leaving get_message_by_id.')
            return r.json()
        else:
            logger.debug('Leaving get_message_by_id.')
            return None

    # Deletes a single message
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     message_id: string. The ID of the message to delete.
    def delete_message(mail_endpoint, token, message_id):
        logger.debug('Entering delete_message.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  message_id: {0}'.format(message_id))

        delete_message = '{0}/Me/Messages/{1}'.format(mail_endpoint, message_id)

        r = make_api_call('DELETE', delete_message, token)

        logger.debug('Leaving delete_message.')

        return r.status_code

    # Updates a single message
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     message_id: string. The ID of the message to update.
    #     update_payload: string. A JSON representation of the properties to =
    #                     update.
    def update_message(mail_endpoint, token, message_id, update_payload):
        logger.debug('Entering update_message.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  message_id: {0}'.format(message_id))
        logger.debug('  update_payload: {0}'.format(update_payload))

        update_message = '{0}/Me/Messages/{1}'.format(mail_endpoint, message_id)

        r = make_api_call('PATCH', update_message, token, update_payload)

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving update_message.')

        return r.status_code

    # Creates a message in the Drafts folder
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     message_payload: string. A JSON representation of the new message.
    def create_message(mail_endpoint, token, message_payload):
        logger.debug('Entering create_message.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  message_payload: {0}'.format(message_payload))

        create_message = '{0}/Me/Messages'.format(mail_endpoint)

        r = make_api_call('POST', create_message, token, message_payload)

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving create_message.')

        return r.status_code

    # Sends an existing message in the Drafts folder
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     message_id: string. The ID of the message to send.
    def send_draft_message(mail_endpoint, token, message_id):
        logger.debug('Entering send_draft_message.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  message_id: {0}'.format(message_id))

        send_message = '{0}/Me/Messages/{1}/Send'.format(mail_endpoint,
                                                         message_id)

        r = make_api_call('POST', send_message, token)

        logger.debug('Leaving send_draft_message.')
        return r.status_code

    # Sends an new message in the Drafts folder
    #   parameters:
    #     mail_endpoint: string. The URL to the Mail API endpoint
    #     token: string. The access token
    #     message_payload: string. The JSON representation of the message.
    #     save_to_sentitems: boolean. True = save a copy in sent items,
    #                        False = don't.
    def send_new_message(mail_endpoint, token, message_payload,
                         save_to_sentitems = True):
        logger.debug('Entering send_new_message.')
        logger.debug('  mail_endpoint: {0}'.format(mail_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  message_payload: {0}'.format(message_payload))
        logger.debug('  save_to_sentitems: {0}'.format(save_to_sentitems))

        send_message = '{0}/Me/SendMail'.format(mail_endpoint)

        message_json = json.loads(message_payload)
        send_message_json = {
            'Message': message_json,
            'SaveToSentItems': str(save_to_sentitems).lower()
        }

        send_message_payload = json.dumps(send_message_json)

        logger.debug('Created payload for send: {0}'
                     .format(send_message_payload))

        r = make_api_call('POST', send_message, token, send_message_payload)

        logger.debug('Leaving send_new_message.')
        return r.status_code

    # Calendar API #

    # Retrieves a set of events from the user's Calendar
    #   parameters:
    #     calendar_endpoint: string. The URL to the Calendar API endpoint
    #     token: string. The access token
    #     parameters: string. An optional string containing query parameters to
    #                 filter, sort, etc.
    def get_events(calendar_endpoint, token, parameters=None):
        logger.debug('Entering get_events.')
        logger.debug('  calendar_endpoint: {0}'.format(calendar_endpoint))
        logger.debug('  token: {0}'.format(token))
        if (not parameters is None):
            logger.debug('  parameters: {0}'.format(parameters))

        get_events = '{0}/Me/Events'.format(calendar_endpoint)

        if (not parameters is None):
            get_events = '{0}{1}'.format(get_events, parameters)

        r = make_api_call('GET', get_events, token)

        if (r.status_code == requests.codes.unauthorized):
            logger.debug('Leaving get_events.')
            return None

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving get_events.')
        return r.json()

    # Retrieves a single event
    #   parameters:
    #     calendar_endpoint: string. The URL to the Calendar API endpoint
    #     token: string. The access token
    #     event_id: string. The ID of the event to retrieve.
    #     parameters: string. An optional string containing query parameters to
    #                 limit the properties returned.
    def get_event_by_id(calendar_endpoint, token, event_id, parameters=None):
        logger.debug('Entering get_event_by_id.')
        logger.debug('  calendar_endpoint: {0}'.format(calendar_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  event_id: {0}'.format(event_id))
        if (not parameters is None):
            logger.debug('  parameters: {0}'.format(parameters))

        get_event = '{0}/Me/Events/{1}'.format(calendar_endpoint, event_id)

        if (not parameters is None and
            parameters != ''):
            get_event = '{0}{1}'.format(get_event, parameters)

        r = make_api_call('GET', get_event, token)

        if (r.status_code == requests.codes.ok):
            logger.debug('Response: {0}'.format(r.json()))
            logger.debug('Leaving get_event_by_id.')
            return r.json()
        else:
            logger.debug('Leaving get_event_by_id.')
            return None

    # Deletes a single event
    #   parameters:
    #     calendar_endpoint: string. The URL to the Calendar API endpoint
    #     token: string. The access token
    #     event_id: string. The ID of the event to delete.
    def delete_event(calendar_endpoint, token, event_id):
        logger.debug('Entering delete_event.')
        logger.debug('  calendar_endpoint: {0}'.format(calendar_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  event_id: {0}'.format(event_id))

        delete_event = '{0}/Me/Events/{1}'.format(calendar_endpoint, event_id)

        r = make_api_call('DELETE', delete_event, token)

        logger.debug('Leaving delete_event.')

        return r.status_code

    # Updates a single event
    #   parameters:
    #     calendar_endpoint: string. The URL to the Calendar API endpoint
    #     token: string. The access token
    #     event_id: string. The ID of the event to update.
    #     update_payload: string. A JSON representation of the properties to
    #                     update.
    def update_event(calendar_endpoint, token, event_id, update_payload):
        logger.debug('Entering update_event.')
        logger.debug('  calendar_endpoint: {0}'.format(calendar_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  event_id: {0}'.format(event_id))
        logger.debug('  update_payload: {0}'.format(update_payload))

        update_event = '{0}/Me/Events/{1}'.format(calendar_endpoint, event_id)

        r = make_api_call('PATCH', update_event, token, update_payload)

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving update_event.')

        return r.status_code

    # Creates an event in the Calendar
    #   parameters:
    #     calendar_endpoint: string. The URL to the Calendar API endpoint
    #     token: string. The access token
    #     event_payload: string. A JSON representation of the new event.
    def create_event(calendar_endpoint, token, event_payload):
        logger.debug('Entering create_event.')
        logger.debug('  calendar_endpoint: {0}'.format(calendar_endpoint))
        logger.debug('  token: {0}'.format(token))
        logger.debug('  event_payload: {0}'.format(event_payload))

        create_event = '{0}/Me/Events'.format(calendar_endpoint)

        r = make_api_call('POST', create_event, token, event_payload)

        logger.debug('Response: {0}'.format(r.json()))
        logger.debug('Leaving create_event.')

        return r.status_code
"""

# MIT License:

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# ""Software""), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED ""AS IS"", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
