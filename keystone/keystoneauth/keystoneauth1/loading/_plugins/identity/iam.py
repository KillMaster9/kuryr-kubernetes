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

import abc
import six

from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1.loading import base


@six.add_metaclass(abc.ABCMeta)
class BaseIamLoader(base.BaseLoader):

    def get_options(self):
        options = super(BaseIamLoader, self).get_options()

        options.extend([
            loading.Opt('endpoint',
                        help='Service endpoint url'),
        ])

        return options


@six.add_metaclass(abc.ABCMeta)
class BaseIdentityLoader(BaseIamLoader):
    """Base Option handling for identity plugins.

    This class defines options and handling that should be common across all
    plugins that are developed against the OpenStack identity service. It
    provides the options expected by the
    :py:class:`keystoneauth1.identity.BaseIdentityPlugin` class.
    """

    def get_options(self):
        options = super(BaseIdentityLoader, self).get_options()

        options.extend([
            loading.Opt('auth-url',
                        required=True,
                        help='Authentication URL'),
            loading.Opt('realm', default='master',
                        help='Realm, default is "master"'),
            loading.Opt('protocol', default='openid-connect',
                        help='Protocol, default is "openid-connect"'),
        ])

        return options


@six.add_metaclass(abc.ABCMeta)
class BaseAuthLoader(BaseIdentityLoader):

    def get_options(self):
        options = super(BaseAuthLoader, self).get_options()

        options.extend([
            loading.Opt('client-id', required=True, help='Client id'),
            loading.Opt('client-secret', help='Client secret'),
            loading.Opt('grant-type', required=True, help='Grant type'),
        ])

        return options


class Password(BaseAuthLoader):

    @property
    def plugin_class(self):
        return identity.IamPassword

    def get_options(self):
        options = super(Password, self).get_options()

        options.extend([
            loading.Opt('username', required=True,
                        help='Username to login with'),
            loading.Opt('password',
                        secret=True,
                        prompt='Password: ',
                        help='Password to use'),
        ])

        return options


class AuthorizationCode(BaseAuthLoader):

    @property
    def plugin_class(self):
        return identity.IamAuthorizationCode

    def get_options(self):
        options = super(AuthorizationCode, self).get_options()

        options.extend([
            loading.Opt('code', required=True,
                        help='Code from IAM identity server'),
            loading.Opt('redirect_uri', required=True,
                        help='Redirect address'),
        ])

        return options


class RefreshToken(BaseAuthLoader):

    @property
    def plugin_class(self):
        return identity.IamRefreshToken

    def get_options(self):
        options = super(RefreshToken, self).get_options()

        options.extend([
            loading.Opt('refresh_token', required=True,
                        help='Refresh token from IAM identity server'),
        ])

        return options


class Token(BaseIamLoader):

    @property
    def plugin_class(self):
        return identity.IamToken

    def get_options(self):
        options = super(Token, self).get_options()

        options.extend([
            loading.Opt('token', required=True,
                        help='Access token from IAM identity server'),
            loading.Opt('token_type', required=True,
                        help='Type of access token'),
        ])

        return options


