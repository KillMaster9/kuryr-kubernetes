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


import webob


class IamAuthResponse(webob.Response):

    default_content_type = None  # prevents webob assigning a content type


class IamAuthRequest(webob.Request):

    ResponseClass = IamAuthResponse

    _IAM_TOKEN_HEADER = 'Authorization'
    _IAM_TOKEN_VALID_HEADER = 'Authorization-Valid'
    _TOKEN_AUTH = 'keystone.token_auth'
    _TOKEN_INFO = 'keystone.token_info'

    @property
    def user_token_valid(self):
        """User token is marked as valid.

        :returns: True if the X-Identity-Status header is set to Confirmed.
        :rtype: bool
        """
        return self.headers[self._IAM_TOKEN_VALID_HEADER]

    @user_token_valid.setter
    def user_token_valid(self, value: bool):
        self.headers[self._IAM_TOKEN_VALID_HEADER] = value

    @property
    def user_token(self):
        return self.headers.get(self._IAM_TOKEN_HEADER, None)

    @property
    def auth_type(self):
        """The authentication type that was performed by the web server.

        The returned string value is always lower case.

        :returns: The AUTH_TYPE environ string or None if not present.
        :rtype: str or None
        """
        try:
            auth_type = self.environ['AUTH_TYPE']
        except KeyError:
            return None
        else:
            return auth_type.lower()

    @property
    def token_auth(self):
        """The auth plugin that will be associated with this request."""
        return self.environ.get(self._TOKEN_AUTH)

    @token_auth.setter
    def token_auth(self, v):
        self.environ[self._TOKEN_AUTH] = v

    @property
    def token_info(self):
        """The raw token dictionary retrieved by the middleware."""
        return self.environ.get(self._TOKEN_INFO)

    @token_info.setter
    def token_info(self, v):
        self.environ[self._TOKEN_INFO] = v
