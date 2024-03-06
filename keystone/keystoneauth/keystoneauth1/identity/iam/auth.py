import abc
import json
import re
import six

from keystoneauth1 import _utils as utils
from keystoneauth1 import exceptions, access
from keystoneauth1.identity.iam import base


LOG = utils.get_logger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseIdentityPlugin(base.BaseAuthPlugin):

    def __init__(self, auth_url, realm=None, protocol=None,
                 endpoint=None, reauthenticate=True):
        LOG.info('Init BaseIdentityPlugin')
        super(BaseIdentityPlugin, self).__init__(auth_url=auth_url,
                                                 endpoint=endpoint,
                                                 reauthenticate=reauthenticate)
        self.realm = realm
        self.protocol = protocol

    @property
    def iam_endpoint(self):
        """The full URL where we will send authentication data."""
        auth_url = self.auth_url.rstrip('/')
        if re.match('^https?://.+/auth/realms/.+/protocol/.+$', auth_url):
            endpoint = auth_url
        else:
            endpoint = '%s/auth/realms/%s/protocol/%s' \
               % (auth_url, self.realm, self.protocol)
        LOG.info('Get IAM endpoint "%s".' % endpoint)
        return endpoint

    def get_endpoint(self, session, service_type=None, service_name=None,
                     **kwargs):
        """Return the supplied endpoint.

        Using this plugin the same endpoint is returned regardless of the
        parameters passed to the plugin. endpoint_override overrides the
        endpoint specified when constructing the plugin.
        """

        endpoint = super(BaseIdentityPlugin, self).get_endpoint(
            session, service_type=service_type, service_name=service_name,
            **kwargs)

        if not endpoint and \
                service_type is 'identity' and \
                service_name is 'iam':
            endpoint = self.iam_endpoint

        return endpoint

    def get_cache_id_elements(self):
        curr_elements = {'auth_url': self.auth_url,
                         'realm': self.realm,
                         'protocol': self.protocol}
        if self.realm:
            curr_elements['realm'] = self.realm
        if self.protocol:
            curr_elements['protocol'] = self.protocol
        elements = super(BaseIdentityPlugin, self).get_cache_id_elements()
        elements.update(curr_elements)
        return elements


class AuthPlugin(BaseIdentityPlugin):

    def __init__(self, auth_url, realm=None, protocol=None,
                 client_id=None, client_secret=None, endpoint=None,
                 grant_type=None, reauthenticate=True):
        LOG.info('Init AuthPlugin')
        super(AuthPlugin, self).__init__(auth_url=auth_url,
                                         realm=realm,
                                         protocol=protocol,
                                         endpoint=endpoint,
                                         reauthenticate=reauthenticate)
        self.client_id = client_id
        self.client_secret = client_secret
        self.grant_type = grant_type

    @property
    def token_url(self):
        """The full URL where we will send authentication data."""

        return '%s/token' % self.iam_endpoint

    def get_auth_ref(self, session, **kwargs):
        headers = {'Accept': 'application/json'}
        rkwargs = {}

        body = self.get_request_body(request_kwargs=rkwargs)
        token_url = self.token_url

        LOG.debug('Making authentication request to %s', token_url)
        resp = session.post(token_url, form=body, headers=headers,
                            authenticated=False, log=False, **rkwargs)

        try:
            LOG.debug(json.dumps(resp.json()))
            resp_data = resp.json()
        except ValueError:
            raise exceptions.InvalidResponse(response=resp)

        if 'access_token' not in resp_data:
            raise exceptions.InvalidResponse(response=resp)

        return access.IamAccessInfo(auth_token=resp_data['access_token'],
                                    body=resp_data)

    def get_cache_id_elements(self):
        elements = {'auth_url': self.auth_url,
                    'realm': self.realm,
                    'protocol': self.protocol,
                    'client_id': self.client_id,
                    'endpoint': self.endpoint,
                    'grant_type': self.grant_type}
        if self.client_secret:
            elements['client_secret'] = self.client_secret
        return elements

    def get_request_body(self, request_kwargs=None):
        body = {'grant_type': self.grant_type,
                'client_id': self.client_id}
        if self.client_secret:
            body['client_secret'] = self.client_secret
        return body


class Password(AuthPlugin):

    def __init__(self, auth_url,
                 realm=None,
                 protocol=None,
                 client_id=None,
                 client_secret=None,
                 endpoint=None,
                 grant_type=None,
                 username=None,
                 password=None,
                 reauthenticate=True):
        LOG.info('Init Password')
        super(Password, self).__init__(auth_url=auth_url,
                                       realm=realm,
                                       protocol=protocol,
                                       client_id=client_id,
                                       client_secret=client_secret,
                                       endpoint=endpoint,
                                       grant_type=grant_type,
                                       reauthenticate=reauthenticate)
        self.username = username
        self.password = password

    def get_request_body(self, request_kwargs=None):
        curr_body = {'username': self.username,
                     'password': self.password}
        body = super(Password, self).get_request_body(request_kwargs)
        body.update(curr_body)
        return body

    def get_cache_id_elements(self):
        curr_elements = {'username': self.username,
                         'password': self.password}
        elements = super(Password, self).get_cache_id_elements()
        elements.update(curr_elements)
        return elements


class AuthorizationCode(AuthPlugin):

    def __init__(self, auth_url,
                 realm=None,
                 protocol=None,
                 client_id=None,
                 client_secret=None,
                 endpoint=None,
                 grant_type=None,
                 code=None,
                 redirect_uri=None,
                 reauthenticate=True):
        LOG.info('Init AuthorizationCode')
        super(AuthorizationCode, self).__init__(
                auth_url=auth_url,
                realm=realm,
                protocol=protocol,
                client_id=client_id,
                client_secret=client_secret,
                endpoint=endpoint,
                grant_type=grant_type,
                reauthenticate=reauthenticate)
        self.code = code
        self.redirect_uri = redirect_uri

    def get_request_body(self, request_kwargs=None):
        curr_body = {'code': self.code,
                     'redirect_uri': self.redirect_uri}
        body = super(AuthorizationCode, self).get_request_body(request_kwargs)
        body.update(curr_body)
        return body

    def get_cache_id_elements(self):
        curr_elements = {'code': self.code,
                         'redirect_uri': self.redirect_uri}
        elements = super(AuthorizationCode, self).get_cache_id_elements()
        elements.update(curr_elements)
        return elements


class RefreshToken(AuthPlugin):

    def __init__(self, auth_url, realm=None, protocol=None,
                 client_id=None, client_secret=None, endpoint=None,
                 grant_type=None, refresh_token=None, reauthenticate=True):
        LOG.info('Init Token')
        super(RefreshToken, self).__init__(
                auth_url=auth_url,
                realm=realm,
                protocol=protocol,
                client_id=client_id,
                client_secret=client_secret,
                endpoint=endpoint,
                grant_type=grant_type,
                reauthenticate=reauthenticate)
        self.refresh_token = refresh_token

    def get_request_body(self, request_kwargs=None):
        curr_body = {'refresh_token': self.refresh_token}
        body = super(RefreshToken, self).get_request_body(request_kwargs)
        body.update(curr_body)
        return body

    def get_cache_id_elements(self):
        curr_elements = {'refresh_token': self.refresh_token}
        elements = super(RefreshToken, self).get_cache_id_elements()
        elements.update(curr_elements)
        return elements


class Token(base.BaseAuthPlugin):

    def __init__(self, token, token_type, endpoint=None):
        LOG.info('Init Token')
        super(Token, self).__init__(endpoint=endpoint)
        self.token = token
        self.token_type = token_type

    def get_cache_id_elements(self):
        elements = {'token': self.token, 'token_type': self.token_type}
        return elements

    def get_auth_ref(self, session, **kwargs):
        body = {'access_token': self.token, 'token_type': self.token_type}
        return access.create(body=body)
