# Copyright (c) 2024 ICOS


import abc
import six

from keystoneauth1 import _utils as utils
from keystoneauth1.identity import base


LOG = utils.get_logger(__name__)
IDENTITY_AUTH_HEADER_NAME = 'Authorization'


@six.add_metaclass(abc.ABCMeta)
class BaseAuthPlugin(base.BaseIdentityPlugin):

    def __init__(self, auth_url=None, endpoint=None, reauthenticate=True):
        LOG.info('Init BaseAuthPlugin')
        super(BaseAuthPlugin, self).__init__(auth_url, reauthenticate)
        self.endpoint = endpoint

    def get_token_type(self, session, **kwargs):
        """Return a valid auth token.

        If a valid token is not present then a new one will be fetched.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :return: A valid token.
        :rtype: string
        """
        return self.get_access(session).token_type

    def get_headers(self, session, **kwargs):
        """Fetch authentication headers for message.

        This is a more generalized replacement of the older get_token to allow
        plugins to specify different or additional authentication headers to
        the OpenStack standard 'X-Auth-Token' header.

        How the authentication headers are obtained is up to the plugin. If the
        headers are still valid they may be re-used, retrieved from cache or
        the plugin may invoke an authentication request against a server.

        The default implementation of get_headers calls the `get_token` method
        to enable older style plugins to continue functioning unchanged.
        Subclasses should feel free to completely override this function to
        provide the headers that they want.

        There are no required kwargs. They are passed directly to the auth
        plugin and they are implementation specific.

        Returning None will indicate that no token was able to be retrieved and
        that authorization was a failure. Adding no authentication data can be
        achieved by returning an empty dictionary.

        :param session: The session object that the auth_plugin belongs to.
        :type session: keystoneauth1.session.Session

        :returns: Headers that are set to authenticate a message or None for
                  failure. Note that when checking this value that the empty
                  dict is a valid, non-failure response.
        :rtype: dict
        """
        token = self.get_token(session)
        token_type = self.get_token_type(session)

        if not token or not token_type:
            return None

        return {IDENTITY_AUTH_HEADER_NAME: '%s %s' % (token_type, token)}

    def get_access(self, session, **kwargs):
        """Fetch or return a current AccessInfo object.

        If a valid AccessInfo is present then it is returned otherwise a new
        one will be fetched.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.http.HttpError: An error from an
                                                         invalid HTTP response.

        :returns: Valid AccessInfo
        :rtype: :class:`keystoneauth1.access.BaseIamAccessInfo`
        """
        return super(BaseAuthPlugin, self).get_access(session, **kwargs)

    @abc.abstractmethod
    def get_auth_ref(self, session, **kwargs):
        """Obtain a token from an OpenStack Identity Service.

        This method is overridden by the various token version plugins.

        This function should not be called independently and is expected to be
        invoked via the do_authenticate function.

        This function will be invoked if the AcessInfo object cached by the
        plugin is not valid. Thus plugins should always fetch a new AccessInfo
        when invoked. If you are looking to just retrieve the current auth
        data then you should use get_access.

        :param session: A session object that can be used for communication.
        :type session: keystoneauth1.session.Session

        :raises keystoneauth1.exceptions.response.InvalidResponse:
            The response returned wasn't appropriate.
        :raises keystoneauth1.exceptions.http.HttpError:
            An error from an invalid HTTP response.

        :returns: Token access information.
        :rtype: :class:`keystoneauth1.access.BaseIamAccessInfo`
        """

    def get_endpoint_data(self, session, **kwargs):
        return None

    def get_endpoint(self, session, endpoint_override=None,
                     endpoint_kwargs=None, **kwargs):
        """Return the supplied endpoint.

        Using this plugin the same endpoint is returned regardless of the
        parameters passed to the plugin. endpoint_override overrides the
        endpoint specified when constructing the plugin.
        """
        endpoint = self.endpoint
        if endpoint_override:
            endpoint = endpoint_override
        if endpoint_kwargs:
            try:
                endpoint = endpoint % endpoint_kwargs
            except KeyError or TypeError as e:
                msg = 'Failed to format endpoint "%s" with endpoint_kwargs' \
                      '"%s": %s' % (endpoint, endpoint_kwargs, e)
                LOG.exception(msg)
                raise ValueError('Failed to format endpoint.')
        return endpoint

    def get_api_major_version(self, session, **kwargs):
        return None

    def get_all_version_data(self, session, **kwargs):
        return {}

    def get_user_id(self, session, **kwargs):
        return None

    def get_project_id(self, session, **kwargs):
        return None

    def get_sp_auth_url(self, session, **kwargs):
        return None

    def get_sp_url(self, session, **kwargs):
        return None

    def get_discovery(self, **kwargs):
        return None

    def get_cache_id_elements(self):
        return {'endpoint', self.endpoint}


class NoAuth(BaseAuthPlugin):

    def __init__(self, endpoint=None):
        LOG.info('Init NoAuth')
        super(NoAuth, self).__init__(endpoint=endpoint, reauthenticate=False)

    def get_token(self, session, **kwargs):
        return 'notoken'

    def get_token_type(self, session, **kwargs):
        return 'noauth'

    def get_auth_ref(self, session, **kwargs):
        return None
