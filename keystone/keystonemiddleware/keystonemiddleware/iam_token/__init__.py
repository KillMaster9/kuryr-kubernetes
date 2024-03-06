# Copyright (c) 2024 ICOS


import jwt
import jwt.exceptions as jwt_exceptions
import webob.dec
import webob.exc

from oslo_log import log as logging
from oslo_serialization import jsonutils

from keystoneauth1 import adapter
from keystoneauth1 import exceptions as ksa_exceptions
from keystoneauth1 import loading as ks_loading
from keystoneauth1.access import access
from keystoneauth1.loading import session as session_loading
from keystonemiddleware._common import config
from keystonemiddleware._common import opts
from keystonemiddleware.i18n import _
from keystonemiddleware.iam_token import auth
from keystonemiddleware.iam_token import exceptions
from keystonemiddleware.iam_token import identity
from keystonemiddleware.iam_token import request


LOG = logging.getLogger(__name__)


class BaseIamAuth(object):
    """A base class for AuthProtocol token checking implementations.

    :param Callable app: The next application to call after middleware.
    :param logging.Logger log: The logging object to use for output. By default
                               it will use a logger in the
                               keystonemiddleware.iam_token namespace.
    """

    def __init__(self, app, log):
        self.log = log
        self._app = app

    @webob.dec.wsgify(RequestClass=request.IamAuthRequest)
    def __call__(self, req):
        """Handle incoming request."""
        response = self.process_request(req)
        if response:
            return response
        response = req.get_response(self._app)
        return self.process_response(response)

    def process_request(self, request):
        """Process request.

        If this method returns a value then that value will be used as the
        response. The next application down the stack will not be executed and
        process_response will not be called.

        Otherwise, the next application down the stack will be executed and
        process_response will be called with the generated response.

        By default this method does not return a value.

        :param request: Incoming request
        :type request: _request.AuthTokenRequest

        """

        if not request.user_token:
            self.log.error('Not find authenticate token')
            request.user_token_valid = False
            return

        try:
            data, user_auth_ref = self.prepare_token(request.user_token)
            self.validate_token(user_auth_ref)
        except exceptions.InvalidToken:
            self.log.exception('Invalid user token')
            request.user_token_valid = False
        else:
            request.user_token_valid = True
            request.token_info = data
            request.token_auth = auth.UserAuthPlugin(
                user_auth_ref=user_auth_ref, log=self.log)

    def prepare_token(self, token, **kwargs):
        self.log.info('Prepare authenticate token')

        try:
            token_type, access_token = token.split(' ')
            data = {'access_token': access_token, 'token_type': token_type}
            auth_ref = access.IamAccessInfo(body=data, auth_token=access_token)
        except ValueError:
            msg = _('Token format should be "<token_type> <access_token>"')
            raise exceptions.InvalidToken(msg)
        data.update({'header': auth_ref.header, 'payload': auth_ref.payload})
        return data, auth_ref

    def validate_token(self, auth_ref, allow_expired=False):
        """Perform the validation steps on the token.

        :param auth_ref: The token data
        :type auth_ref: keystoneauth1.access.BaseIamAccessInfo

        :raises exc.InvalidToken: if token is rejected
        """
        self.log.info('Validate token expired or not')

        # 0 seconds of validity means it is invalid right now
        if (not allow_expired) and auth_ref.will_expire_soon(stale_duration=0):
            raise exceptions.InvalidToken(_('Token authorization failed'))

    def process_response(self, response):
        """Do whatever you'd like to the response.

        By default the response is returned unmodified.

        :param response: Response object
        :type response: ._request._AuthTokenResponse
        """
        return response


class IamAuth(BaseIamAuth):

    def __init__(self, app, conf):
        self._conf = config.Config('iam_token',
                                   opts.AUTHTOKEN_GROUP,
                                   opts.list_opts(),
                                   conf)
        log = logging.getLogger(conf.get('log_name', __name__))
        log.info('Starting Keystone iam_token middleware')

        # TODO(zhuyawei) 暂不实现 add memcache

        super(IamAuth, self).__init__(app, log=log)

        self._hash_algorithms = self._conf.get('hash_algorithms')

        self._auth = self._create_auth_plugin()
        self._session = self._create_session()
        self._identity_server = self._create_identity_server()

        self._www_authenticate_uri = self._conf.get('www_authenticate_uri')
        if not self._www_authenticate_uri:
            self.log.warning(
                'Configuring www_authenticate_uri to the iam identity endpoint'
                ' is required.')

            self._www_authenticate_uri = \
                self._identity_server.www_authenticate_uri

    def _create_auth_plugin(self):
        group = self._conf.get('auth_section') or opts.AUTHTOKEN_GROUP
        plugin_name = self._conf.get('auth_type', group=group)

        if not plugin_name:
            return auth.IamTokenPlugin.load_from_conf(
                conf=self._conf, group=group, log=self.log)

        plugin_loader = ks_loading.get_plugin_loader(plugin_name)
        plugin_opts = ks_loading.get_auth_plugin_conf_options(plugin_loader)
        self._conf.oslo_conf_obj.register_opts(plugin_opts, group=group)
        getter = lambda opt: self._conf.get(opt.dest, group=group)
        return plugin_loader.load_from_options_getter(getter)

    def _create_session(self, **kwargs):
        kwargs.setdefault('cert', self._conf.get('certfile'))
        kwargs.setdefault('key', self._conf.get('keyfile'))
        kwargs.setdefault('cacert', self._conf.get('cafile'))
        kwargs.setdefault('insecure', self._conf.get('insecure'))
        kwargs.setdefault('timeout', self._conf.get('http_connect_timeout'))
        kwargs.setdefault('user_agent', self._conf.user_agent)
        return session_loading.Session().load_from_options(**kwargs)

    def _create_identity_server(self):
        adap = adapter.UrlEncodeAdapter(
            session=self._session,
            auth=self._auth,
            service_type='identity',
            service_name='iam',
            connect_retries=self._conf.get('http_request_max_retries'))

        auth_version = self._conf.get('auth_version')
        return identity.IdentityServer(
            self.log,
            adap,
            requested_auth_version=auth_version)

    def process_request(self, request):
        """Process request.

        If this method returns a value then that value will be used as the
        response. The next application down the stack will not be executed and
        process_response will not be called.

        Otherwise, the next application down the stack will be executed and
        process_response will be called with the generated response.

        By default this method does not return a value.

        :param request: Incoming request
        :type request: _request.AuthTokenRequest

        """
        self.log.info('Authenticating user token')

        resp = super(IamAuth, self).process_request(request)
        if resp:
            return resp

        if not request.user_token_valid:
            self.log.info('Rejecting request')
            message = _('The request you have made requires '
                        'authentication.')
            body = {'error': {
                'code': 401,
                'title': 'Unauthorized',
                'message': message,
            }}
            raise webob.exc.HTTPUnauthorized(
                body=jsonutils.dumps(body),
                headers=self._reject_auth_headers,
                charset='UTF-8',
                content_type='application/json')

        if request.token_auth:
            request.token_auth._auth = self._auth
            request.token_auth._session = self._session

    def process_response(self, response):
        """Process Response.

        Add ``WWW-Authenticate`` headers to requests that failed with
        ``401 Unauthenticated`` so users know where to authenticate for future
        requests.
        """
        if response.status_int == 401:
            response.headers.extend(self._reject_auth_headers)

        return response

    def validate_token(self, auth_ref, allow_expired=False):
        super(IamAuth, self).validate_token(auth_ref, allow_expired)

        # offline validate
        self.offline_validate_token(auth_ref)

        # online validate
        # TODO(zhuyawei) 暂不实现

    def offline_validate_token(self, auth_ref):
        self.log.info('Validate token offline')

        kid = auth_ref.header['kid']
        try:
            cert = self._identity_server.fetch_cert(kid)
        except ksa_exceptions.NotFound:
            self.log.exception('Not found cert for kid "%s"' % (kid,))
            raise exceptions.InvalidToken(_('Token authorization failed'))

        data = None
        options = {'verify_aud': False}
        for x5c in cert['x5c']:
            try:
                data = jwt.decode(auth_ref.auth_token, key=x5c['pubkey'],
                                  options=options)
                break
            except jwt_exceptions.DecodeError:
                self.log.exception('Token decode failed')
            except jwt_exceptions.InvalidAlgorithmError:
                self.log.exception('Token algorithm failed')
            except jwt_exceptions.ExpiredSignatureError:
                self.log.exception('Token expired')
            except:
                self.log.exception('Token parse error')
        if not data:
            raise exceptions.InvalidToken(_('Token authorization failed'))
        return data

    @property
    def _reject_auth_headers(self):
        header_val = 'IAM uri="%s"' % self._www_authenticate_uri
        return [('WWW-Authenticate', header_val)]


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return IamAuth(app, conf)

    return auth_filter


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return IamAuth(None, conf)
