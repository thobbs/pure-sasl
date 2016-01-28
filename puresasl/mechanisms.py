import base64
import hashlib
import hmac
import struct
import sys

from puresasl import SASLError, SASLProtocolException, QOP

try:
    import kerberos
    _have_kerberos = True
except ImportError:
    _have_kerberos = False

PY3 = sys.version_info[0] == 3
if PY3:
    def _b(s):
        return s.encode("utf-8")
else:
    def _b(s):
        return s


class Mechanism(object):
    """
    The base class for all mechanisms.
    """

    name = None
    """ The IANA registered name for the mechanism. """

    score = 0
    """ A relative security score where higher scores correspond
    to more secure mechanisms. """

    complete = False
    """ Set to True when SASL negotiation has completed succesfully. """

    has_initial_response = False

    allows_anonymous = True
    """ True if the mechanism allows for anonymous logins. """

    uses_plaintext = True
    """ True if the mechanism transmits sensitive information in plaintext. """

    active_safe = False
    """ True if the mechanism is safe against active attacks. """

    dictionary_safe = False
    """ True if the mechanism is safe against passive dictionary attacks. """

    def __init__(self, sasl, **props):
        self.sasl = sasl

    def process(self, challenge=None):
        """
        Process a challenge request and return the response.

        :param challenge: A challenge issued by the server that
                          must be answered for authentication.
        """
        raise NotImplementedError()

    def wrap(self, outgoing):
        """
        Wrap an outgoing message intended for the SASL server. Depending
        on the negotiated quality of protection, this may result in the
        message being signed, encrypted, or left unaltered.
        """
        raise NotImplementedError()

    def unwrap(self, incoming):
        """
        Unwrap a message from the SASL server. Depending on the negotiated
        quality of protection, this may check a signature, decrypt the message,
        or leave the message unaltered.
        """
        raise NotImplementedError()

    def dispose(self):
        """
        Clear all sensitive data, such as passwords.
        """
        pass

    def _fetch_properties(self, *properties):
        """
        Ensure this mechanism has the needed properties. If they haven't
        been set yet, the registered callback function will be called for
        each property to retrieve a value.
        """
        needed = [p for p in properties if getattr(self, p, None) is None]
        if needed and not self.sasl.callback:
            raise SASLError('The following properties are required, but a '
                            'callback has not been set: %s' % ', '.join(needed))

        for prop in needed:
            setattr(self, prop, self.sasl.callback(prop))

    def _pick_qop(self, server_qop_set):
        """
        Choose a quality of protection based on the user's requirements and
        what the server supports.
        """
        configured_qops = set(_b(qop) if isinstance(qop, str) else qop for qop in self.sasl.qops)  # normalize user-defined config
        available_qops = configured_qops & server_qop_set
        if not available_qops:
            configured = b', '.join(configured_qops).decode('ascii')
            offered = b', '.join(server_qop_set).decode('ascii')
            raise SASLProtocolException("Your requested quality of "
                                        "protection is one of (%s), but the server is only "
                                        "offering (%s)" % (configured, offered))
        else:
            self.qops = available_qops
            for qop in (QOP.AUTH_CONF, QOP.AUTH_INT, QOP.AUTH):
                if qop in self.qops:
                    self.qop = qop
                    break


class AnonymousMechanism(Mechanism):
    """
    An anonymous user login mechanism.
    """
    name = 'ANONYMOUS'
    score = 0

    uses_plaintext = False

    def process(self, challenge=None):
        self.complete = True
        return b'Anonymous, None'


class PlainMechanism(Mechanism):
    """
    A plaintext user/password based mechanism.
    """
    name = 'PLAIN'
    score = 1

    allows_anonymous = False

    def wrap(self, outgoing):
        return outgoing

    def unwrap(self, incoming):
        return incoming

    def __init__(self, sasl, username=None, password=None, identity='', **props):
        Mechanism.__init__(self, sasl)
        self.identity = identity
        self.username = username
        self.password = password

    def process(self, challenge=None):
        self._fetch_properties('username', 'password')
        self.complete = True
        return b''.join((_b(self.identity), b'\x00', _b(self.username), b'\x00', _b(self.password)))

    def dispose(self):
        self.password = None


class CramMD5Mechanism(PlainMechanism):
    name = "CRAM-MD5"
    score = 20

    allows_anonymous = False
    uses_plaintext = False

    def __init__(self, sasl, username=None, password=None, **props):
        Mechanism.__init__(self, sasl)
        self.username = username
        self.password = password

    def process(self, challenge=None):
        if challenge is None:
            return None

        self._fetch_properties('username', 'password')
        mac = hmac.HMAC(key=_b(self.password), digestmod=hashlib.md5)
        mac.update(challenge)
        return b''.join((_b(self.username), b' ', _b(mac.hexdigest())))

    def dispose(self):
        self.password = None


# TODO: incomplete, not tested
class DigestMD5Mechanism(Mechanism):

    name = "DIGEST-MD5"
    score = 30

    allows_anonymous = False
    uses_plaintext = False

    enc_magic = 'Digest session key to client-to-server signing key magic'
    dec_magic = 'Digest session key to server-to-client signing key magic'

    def __init__(self, sasl, username=None, password=None, **props):
        raise NotImplementedError("Digest MD5 mechanism is not yet supported")


class GSSAPIMechanism(Mechanism):
    name = 'GSSAPI'
    score = 100

    allows_anonymous = False
    uses_plaintext = False
    active_safe = True

    def __init__(self, sasl, principal=None, **props):
        Mechanism.__init__(self, sasl)
        self.user = None
        self._have_negotiated_details = False
        self.host = self.sasl.host
        self.service = self.sasl.service
        self.principal = principal
        self._fetch_properties('host', 'service')

        krb_service = '@'.join((self.service, self.host))
        try:
            _, self.context = kerberos.authGSSClientInit(service=krb_service,
                                                         principal=self.principal)
        except TypeError:
            if self.principal is not None:
                raise Exception("Error: kerberos library does not support principal.")
            _, self.context = kerberos.authGSSClientInit(service=krb_service)

    def process(self, challenge=None):
        if not self._have_negotiated_details:
            kerberos.authGSSClientStep(self.context, '')
            _negotiated_details = kerberos.authGSSClientResponse(self.context)
            self._have_negotiated_details = True
            return base64.b64decode(_negotiated_details)

        challenge = base64.b64encode(challenge).decode('ascii')  # kerberos methods expect strings, not bytes
        if self.user is None:
            ret = kerberos.authGSSClientStep(self.context, challenge)
            if ret == kerberos.AUTH_GSS_COMPLETE:
                self.user = kerberos.authGSSClientUserName(self.context)
                return b''
            else:
                response = kerberos.authGSSClientResponse(self.context)
                if response:
                    response = base64.b64decode(response)
                else:
                    response = b''
            return response

        kerberos.authGSSClientUnwrap(self.context, challenge)
        data = kerberos.authGSSClientResponse(self.context)
        plaintext_data = base64.b64decode(data)
        if len(plaintext_data) != 4:
            raise SASLProtocolException("Bad response from server")  # todo: better message

        word, = struct.unpack('!I', plaintext_data)
        qop_bits = word >> 24
        max_length = word & 0xffffff
        server_offered_qops = QOP.names_from_bitmask(qop_bits)
        self._pick_qop(server_offered_qops)

        self.max_buffer = min(self.sasl.max_buffer, max_length)

        """
        byte 0: the selected qop. 1==auth, 2==auth-int, 4==auth-conf
        byte 1-3: the max length for any buffer sent back and forth on
            this connection. (big endian)
        the rest of the buffer: the authorization user name in UTF-8 -
            not null terminated.
        """
        l = len(self.user)
        fmt = '!I' + str(l) + 's'
        word = QOP.flag_from_name(self.qop) << 24 | self.max_buffer
        out = struct.pack(fmt, word, _b(self.user),)

        encoded = base64.b64encode(out).decode('ascii')

        kerberos.authGSSClientWrap(self.context, encoded)
        response = kerberos.authGSSClientResponse(self.context)
        self.complete = True
        return base64.b64decode(response)

    def wrap(self, outgoing):
        if self.qop != 'auth':
            outgoing = base64.b64encode(outgoing)
            if self.qop == 'auth-conf':
                protect = 1
            else:
                protect = 0
            kerberos.authGSSClientWrap(self.context, outgoing, None, protect)
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return outgoing

    def unwrap(self, incoming):
        if self.qop != 'auth':
            incoming = base64.b64encode(incoming)
            kerberos.authGSSClientUnwrap(self.context, incoming)
            conf = kerberos.authGSSClientResponseConf(self.context)
            if 0 == conf and self.qop == 'auth-conf':
                raise Exception("Error: confidentiality requested, but not honored by the server.")
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return incoming

    def dispose(self):
        kerberos.authGSSClientClean(self.context)


#: Global registry mapping mechanism names to implementation classes.
mechanisms = dict((m.name, m) for m in (
    AnonymousMechanism,
    PlainMechanism,
    CramMD5Mechanism,
    DigestMD5Mechanism))

if _have_kerberos:
    mechanisms[GSSAPIMechanism.name] = GSSAPIMechanism
