try:
    import unittest2 as unittest
except ImportError:
    import unittest  # noqa

import base64
import hashlib
import hmac
import platform
if platform.system() == 'Windows':
    import winkerberos as kerberos
else:
    import kerberos

from mock import patch
import six
import struct

from puresasl import SASLProtocolException, QOP
from puresasl.client import SASLClient
from puresasl.mechanisms import AnonymousMechanism, PlainMechanism, GSSAPIMechanism, DigestMD5Mechanism, CramMD5Mechanism, ExternalMechanism


class _BaseMechanismTests(unittest.TestCase):

    mechanism_class = AnonymousMechanism
    sasl_kwargs = {}

    def setUp(self):
        self.sasl = SASLClient('localhost', mechanism=self.mechanism_class.name, **self.sasl_kwargs)
        self.mechanism = self.sasl._chosen_mech

    def test_init_basic(self, *args):
        sasl = SASLClient('localhost', mechanism=self.mechanism_class.name, **self.sasl_kwargs)
        mech = sasl._chosen_mech
        self.assertIs(mech.sasl, sasl)
        self.assertIsInstance(mech, self.mechanism_class)

    def test_process_basic(self, *args):
        self.assertIsInstance(self.sasl.process(six.b('string')), six.binary_type)
        self.assertIsInstance(self.sasl.process(six.b('string')), six.binary_type)

    def test_dispose_basic(self, *args):
        self.sasl.dispose()

    def test_wrap_unwrap(self, *args):
        self.assertRaises(NotImplementedError, self.sasl.wrap, 'msg')
        self.assertRaises(NotImplementedError, self.sasl.unwrap, 'msg')

    def test__pick_qop(self, *args):
        self.assertRaises(SASLProtocolException, self.sasl._chosen_mech._pick_qop, set())
        self.sasl._chosen_mech._pick_qop(set(QOP.all))


class AnonymousMechanismTest(_BaseMechanismTests):

    mechanism_class = AnonymousMechanism


class PlainTextMechanismTest(_BaseMechanismTests):

    mechanism_class = PlainMechanism
    username = 'user'
    password = 'pass'
    sasl_kwargs = {'username': username, 'password': password}

    def test_process(self):
        for challenge in (None, '', b'asdf', u"\U0001F44D"):
            response = self.sasl.process(challenge)
            self.assertEqual(response, six.b('\x00{0}\x00{1}'.format(self.username, self.password)))
            self.assertIsInstance(response, six.binary_type)

    def test_process_with_authorization_id_or_identity(self):
        challenge = u"\U0001F44D"
        identity = 'user2'

        # Test that we can pass an identity
        sasl_kwargs = self.sasl_kwargs.copy()
        sasl_kwargs.update({'identity': identity})
        sasl = SASLClient('localhost', mechanism=self.mechanism_class.name, **sasl_kwargs)
        response = sasl.process(challenge)
        self.assertEqual(response, six.b('{0}\x00{1}\x00{2}'.format(identity, self.username, self.password)))
        self.assertIsInstance(response, six.binary_type)
        self.assertTrue(sasl.complete)

        # Test that the sasl authorization_id has priority over identity
        auth_id = 'user3'
        sasl_kwargs.update({'authorization_id': auth_id})
        sasl = SASLClient('localhost', mechanism=self.mechanism_class.name, **sasl_kwargs)
        response = sasl.process(challenge)
        self.assertEqual(response, six.b('{0}\x00{1}\x00{2}'.format(auth_id, self.username, self.password)))
        self.assertIsInstance(response, six.binary_type)
        self.assertTrue(sasl.complete)

    def test_wrap_unwrap(self):
        msg = 'msg'
        self.assertIs(self.sasl.wrap(msg), msg)
        self.assertIs(self.sasl.unwrap(msg), msg)


class ExternalMechanismTest(_BaseMechanismTests):

    mechanism_class = ExternalMechanism

    def test_process(self):
        self.assertIs(self.sasl.process(), b'')

    def test_wrap_unwrap(self):
        msg = 'msg'
        self.assertIs(self.sasl.wrap(msg), msg)
        self.assertIs(self.sasl.unwrap(msg), msg)


@patch('puresasl.mechanisms.kerberos.authGSSClientStep')
@patch('puresasl.mechanisms.kerberos.authGSSClientResponse', return_value=base64.b64encode(six.b('some\x00 response')))
class GSSAPIMechanismTest(_BaseMechanismTests):

    mechanism_class = GSSAPIMechanism
    service = 'GSSAPI'
    sasl_kwargs = {'service': service}

    @patch('puresasl.mechanisms.kerberos.authGSSClientWrap')
    @patch('puresasl.mechanisms.kerberos.authGSSClientUnwrap')
    def test_wrap_unwrap(self, _inner1, _inner2, authGSSClientResponse, *args):
        # bypassing process setup by setting qop directly
        self.mechanism.qop = QOP.AUTH
        msg = b'msg'
        self.assertIs(self.sasl.wrap(msg), msg)
        self.assertIs(self.sasl.unwrap(msg), msg)

        for qop in (QOP.AUTH_INT, QOP.AUTH_CONF):
            self.mechanism.qop = qop
            with patch('puresasl.mechanisms.kerberos.authGSSClientResponseConf', return_value=1):
                self.assertEqual(self.sasl.wrap(msg), base64.b64decode(authGSSClientResponse.return_value))
                self.assertEqual(self.sasl.unwrap(msg), base64.b64decode(authGSSClientResponse.return_value))
            if qop == QOP.AUTH_CONF:
                with patch('puresasl.mechanisms.kerberos.authGSSClientResponseConf', return_value=0):
                    self.assertRaises(Exception, self.sasl.unwrap, msg)

    def test_process_no_user(self, authGSSClientResponse, *args):
        msg = six.b('whatever')

        # no user
        self.assertEqual(self.sasl.process(msg), base64.b64decode(authGSSClientResponse.return_value))
        with patch('puresasl.mechanisms.kerberos.authGSSClientResponse', return_value=''):
            self.assertEqual(self.sasl.process(msg), six.b(''))

        username = 'username'
        # user; this has to be last because it sets mechanism.user
        with patch('puresasl.mechanisms.kerberos.authGSSClientStep', return_value=kerberos.AUTH_GSS_COMPLETE):
            with patch('puresasl.mechanisms.kerberos.authGSSClientUserName', return_value=six.b(username)):
                self.assertEqual(self.sasl.process(msg), six.b(''))
                self.assertEqual(self.mechanism.user, six.b(username))

    @patch('puresasl.mechanisms.kerberos.authGSSClientUnwrap')
    def test_process_qop(self, *args):
        self.mechanism._have_negotiated_details = True
        self.mechanism.user = 'user'
        msg = six.b('msg')
        # default patch returns an invalid response for this phase
        self.assertRaises(SASLProtocolException, self.sasl.process, msg)

        max_len = 100
        self.assertLess(max_len, self.sasl.max_buffer)
        for i, qop in QOP.bit_map.items():
            qop_size = struct.pack('!i', i << 24 | max_len)
            response = base64.b64encode(qop_size)
            with patch('puresasl.mechanisms.kerberos.authGSSClientResponse', return_value=response):
                with patch('puresasl.mechanisms.kerberos.authGSSClientWrap') as authGSSClientWrap:
                    self.mechanism.complete = False
                    self.assertEqual(self.sasl.process(msg), qop_size)
                    self.assertTrue(self.mechanism.complete)
                    self.assertEqual(self.mechanism.qop, qop)
                    self.assertEqual(self.mechanism.max_buffer, max_len)

                    args = authGSSClientWrap.call_args[0]
                    out_data = args[1]
                    out = base64.b64decode(out_data)
                    self.assertEqual(out[:4], qop_size)
                    self.assertEqual(out[4:], six.b(self.mechanism.user))

    @patch('puresasl.mechanisms.kerberos.authGSSClientClean')
    def test_dispose_basic(self, authGSSClientUnwrap, *args):
        self.sasl.dispose()
        authGSSClientUnwrap.assert_called_once_with(self.mechanism.context)


class CramMD5MechanismTest(_BaseMechanismTests):

    mechanism_class = CramMD5Mechanism
    username = 'user'
    password = 'pass'
    sasl_kwargs = {'username': username, 'password': password}

    def test_process(self):
        self.assertIsNone(self.sasl.process(None))
        challenge = six.b('msg')
        hash = hmac.HMAC(key=six.b(self.password), digestmod=hashlib.md5)
        hash.update(challenge)
        response = self.sasl.process(challenge)
        self.assertIn(six.b(self.username), response)
        self.assertIn(six.b(hash.hexdigest()), response)
        self.assertIsInstance(response, six.binary_type)
        self.assertTrue(self.sasl.complete)

    def test_wrap_unwrap(self):
        msg = 'msg'
        self.assertIs(self.sasl.wrap(msg), msg)
        self.assertIs(self.sasl.unwrap(msg), msg)


class DigestMD5MechanismTest(_BaseMechanismTests):

    mechanism_class = DigestMD5Mechanism
    username = 'user'
    password = 'pass'
    sasl_kwargs = {'username': username, 'password': password}

    def test_wrap_unwrap(self):
        msg = 'msg'
        self.assertIs(self.sasl.wrap(msg), msg)
        self.assertIs(self.sasl.unwrap(msg), msg)

    def test_process_basic(self, *args):
        pass

    def test_process(self):
        testChallenge = (
            b'nonce="rmD6R8aMYVWH+/ih9HGBr3xNGAR6o2DUxpKlgDz6gUQ=",r'
            b'ealm="example.org",qop="auth,auth-int,auth-conf",cipher="rc4-40,rc'
            b'4-56,rc4,des,3des",maxbuf=65536,charset=utf-8,algorithm=md5-sess'
        )
        self.sasl.process(testChallenge)

    def test_process_server_answer(self):
        sasl_kwargs = {'username': "chris", 'password': "secret"}
        sasl = SASLClient('elwood.innosoft.com',
                          service="imap",
                          mechanism=self.mechanism_class.name,
                          mutual_auth=True,
                          **sasl_kwargs)
        testChallenge = (
            b'utf-8,username="chris",realm="elwood.innosoft.com",'
            b'nonce="OA6MG9tEQGm2hh",nc=00000001,cnonce="OA6MHXh6VqTrRk",'
            b'digest-uri="imap/elwood.innosoft.com",'
            b'response=d388dad90d4bbd760a152321f2143af7,qop=auth'
        )
        sasl.process(testChallenge)
        # cnonce is generated randomly so we have to set it so
        # we assert the expected value
        sasl._chosen_mech.cnonce = b"OA6MHXh6VqTrRk"

        serverResponse = (
            b'rspauth=ea40f60335c427b5527b84dbabcdfffd'
        )
        sasl.process(serverResponse)

    def test__pick_qop(self):
        # _pick_qop is called by process for DigestMD5
        # assert that it chose the only supported mech
        self.assertEqual(self.sasl.qop, QOP.AUTH)
