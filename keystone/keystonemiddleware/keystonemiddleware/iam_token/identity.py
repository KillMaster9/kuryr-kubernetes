# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import base64
import datetime
import six

from keystoneauth1 import exceptions as ksa_exceptions
from keystoneauth1 import plugin
from keystoneauth1 import _utils as utils
from keystonemiddleware.iam_token import exceptions as ksm_exceptions
from keystonemiddleware.iam_token import certs
from keystonemiddleware.i18n import _


class IdentityServer(object):
    """Base class for operations on the Identity API server.

    The auth_token middleware needs to communicate with the Identity API server
    to validate UUID tokens, fetch the revocation list, signing certificates,
    etc. This class encapsulates the data and methods to perform these
    operations.

    """

    def __init__(self, log, adap, requested_auth_version=None):
        self._LOG = log
        self._adapter = adap
        self._requested_auth_version = requested_auth_version
        self._certs = {}
        self._last_update_certs = None

    @property
    def www_authenticate_uri(self):
        www_authenticate_uri = self._adapter.get_endpoint(
            interface=plugin.AUTH_INTERFACE)

        return www_authenticate_uri

    @property
    def auth_version(self):
        return self._requested_auth_version

    def verify_token(self, user_token, retry=True, allow_expired=False):
        """Authenticate user token with identity server.

        :param user_token: user's token id
        :param retry: flag that forces the middleware to retry
                      user authentication when an indeterminate
                      response is received. Optional.
        :param allow_expired: Allow retrieving an expired token.
        :returns: access info received from identity server on success
        :rtype: :py:class:`keystoneauth1.access.BaseIamAccessInfo`
        :raises exc.InvalidToken: if token is rejected
        :raises exc.ServiceError: if unable to authenticate token

        """
        try:
            return self._do_verify_token(user_token,
                                         allow_expired=allow_expired)
        except ksa_exceptions.NotFound as e:
            self._LOG.info('Authorization failed for token')
            self._LOG.info('Identity response: %s', e.response.text)
            raise ksm_exceptions.InvalidToken(_('Token authorization failed'))
        except ksa_exceptions.Unauthorized as e:
            self._LOG.info('Identity server rejected authorization')
            self._LOG.warning('Identity response: %s', e.response.text)
            if retry:
                self._LOG.info('Retrying validation')
                return self.verify_token(user_token, False)
            msg = _('Identity server rejected authorization necessary to '
                    'fetch token data')
            raise ksm_exceptions.ServiceError(msg)
        except ksa_exceptions.HttpError as e:
            self._LOG.error(
                'Bad response code while validating token: %s %s',
                e.http_status, e.message)
            if hasattr(e.response, 'text'):
                self._LOG.warning('Identity response: %s', e.response.text)
            msg = _('Failed to fetch token data from identity server')
            raise ksm_exceptions.ServiceError(msg)

    def _do_verify_token(self, user_token, allow_expired=False):
        # TODO(zhuyawei) 暂不实现 online validate token
        # -H 'Authorization:<base64 client_id:client_secret>'
        client_id = self._adapter.auth.client_id
        client_secret = self._adapter.auth.client_secret
        msg = '%s:%s' % (client_id, client_secret)
        if six.PY3:
            msg = msg.encode()
        encoded = base64.urlsafe_b64encode(msg)
        if six.PY3:
            encoded = encoded.decode()
        headers = {'Authorization': encoded}
        body = {'token': user_token, 'token_type_hint': 'access_token'}
        return self._adapter.post('/token/introspect', headers=headers,
                                  body=body, authenticated=False)

    def need_update_certs(self):
        now = datetime.datetime.utcnow()
        return not self._last_update_certs or self._last_update_certs < now

    def fetch_certs(self):
        if not self.need_update_certs():
            self._LOG.debug('Not need fetch certs')
            return
        self._LOG.info('Fetch certs')
        resp, body = self._adapter.get('/certs', authenticated=False)
        certs_ = certs.load_certs(body)
        self._certs.update(certs_)
        self._last_update_certs = utils.from_utcnow(seconds=300)

    def fetch_cert(self, kid):
        self._LOG.info('Fetch cert kid=%s', kid)
        if kid in self._certs:
            return self._certs[kid]
        self.fetch_certs()
        if kid in self._certs:
            return self._certs[kid]
        msg = _('Not found cert for kid "%s"' % (kid,))
        raise ksa_exceptions.NotFound(msg)

