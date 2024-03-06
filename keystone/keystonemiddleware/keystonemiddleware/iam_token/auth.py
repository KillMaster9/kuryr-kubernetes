# Copyright (c) 2024 ICOS


from oslo_config import cfg
from oslo_log import log as logging

from keystoneauth1.identity import iam
from keystonemiddleware._common import opts


LOG = logging.getLogger(__name__)
IDENTITY_AUTH_HEADER_NAME = 'Authorization'


class IamTokenPlugin(iam.BaseIdentityPlugin):

    def __init__(self, auth_url, realm=None, protocol=None,
                 client_id=None, client_secret=None, log=None):
        self.log = log or LOG
        self.log.info('Init IamTokenPlugin')
        super(IamTokenPlugin, self).__init__(auth_url=auth_url,
                                             realm=realm,
                                             protocol=protocol,
                                             reauthenticate=False)
        self.client_id = client_id
        self.client_secret = client_secret

    def get_auth_ref(self, session, **kwargs):
        self.log.error('IamTokenPlugin no auth_ref')
        return None

    @classmethod
    def get_options(cls):
        options = [
            cfg.StrOpt('auth-url',
                       required=True,
                       help='Authentication URL'),
            cfg.StrOpt('realm', default='master',
                       help='Realm, default is "master"'),
            cfg.StrOpt('protocol', default='openid-connect',
                       help='Protocol, default is "openid-connect"'),
        ]
        return options

    @classmethod
    def load_from_conf(cls, conf, group=None, **kwargs):
        group = group or opts.AUTHTOKEN_GROUP
        options = cls.get_options()
        conf.oslo_conf_obj.register_opts(options, group=group)
        kwargs.update({opt.dest: conf.get(opt.dest, group=group)
                       for opt in options if opt.dest not in kwargs})
        return cls(**kwargs)


class UserAuthPlugin(iam.BaseAuthPlugin):

    def __init__(self, user_auth_ref, endpoint=None,
                 session=None, auth=None, log=None):
        self.log = log or LOG
        self.log.info('Init UserAuthPlugin')
        super(UserAuthPlugin, self).__init__(endpoint=endpoint,
                                             reauthenticate=False)
        self.user = user_auth_ref
        self.auth = auth
        self.session = session

    def get_auth_ref(self, session, **kwargs):
        return self.user

    @property
    def has_user_token(self):
        """Did this authentication request contained a user auth token."""
        return self.user is not None
