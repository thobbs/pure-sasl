import base64
import hashlib
import hmac
import struct

from ctypes import create_string_buffer
from puresasl import SASLError, SASLProtocolException
from puresasl.util import bytes

try:
    import kerberos
    _have_kerberos = True
except ImportError:
    _have_kerberos = False


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

    def __init__(self, sasl):
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

    def _pick_qop(self, server_offered_qops):
        """
        Choose a quality of protection based on the user's requirements and
        what the server supports.
        """
        available_qops = set(self.sasl.qops) & set(server_offered_qops)
        if not available_qops:
            raise SASLProtocolException("Your requested quality of "
                    "protection is one of (%s), but the server is only "
                    "offering (%s)" %
                    (', '.join(self.sasl.qops), ', '.join(server_offered_qops)))
        else:
            self.qops = available_qops
            for qop in ('auth-conf', 'auth-int', 'auth'):
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
        return bytes(self.identity) + b'\x00' + bytes(self.username) + b'\x00' + bytes(self.password)

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
        mac = hmac.HMAC(key=bytes(self.password), digestmod=hashlib.md5)
        mac.update(challenge)
        return bytes(self.username) + b' ' + bytes(mac.hexdigest())

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

        krb_service = b'@'.join((bytes(self.service), bytes(self.host)))
        try:
            _, self.context = kerberos.authGSSClientInit(
                    service=krb_service, principal=self.principal)
        except TypeError:
            if self.principal is not None:
                raise StandardError("Error: kerberos library does not support principal.")
            _, self.context = kerberos.authGSSClientInit(
                    service=krb_service)

    def process(self, challenge=None):
        if not self._have_negotiated_details:
            kerberos.authGSSClientStep(self.context, '')
            _negotiated_details = kerberos.authGSSClientResponse(self.context)
            self._have_negotiated_details = True
            return base64.b64decode(_negotiated_details)

        challenge = base64.b64encode(challenge)
        if self.user is None:
            ret = kerberos.authGSSClientStep(self.context, challenge)
            if ret == kerberos.AUTH_GSS_COMPLETE:
                self.user = kerberos.authGSSClientUserName(self.context)
                return ''
            else:
                response = kerberos.authGSSClientResponse(self.context)
                if response:
                    response = base64.b64decode(response)
                else:
                    response = ''
            return response

        kerberos.authGSSClientUnwrap(self.context, challenge)
        data = kerberos.authGSSClientResponse(self.context)
        plaintext_data = base64.b64decode(data)
        if len(plaintext_data) != 4:
            raise SASLProtocolException("Bad response from server")  # todo: better message

        layers_supported, = struct.unpack('B', plaintext_data[0])
        server_offered_qops = []
        if 0x01 & layers_supported:
            server_offered_qops.append('auth')
        if 0x02 & layers_supported:
            server_offered_qops.append('auth-int')
        if 0x04 & layers_supported:
            server_offered_qops.append('auth-conf')

        self._pick_qop(server_offered_qops)

        max_length, = struct.unpack('!i', '\x00' + plaintext_data[1:])
        self.max_buffer = min(self.sasl.max_buffer, max_length)

        """
        Construct the reply.

        byte 0: the selected qop. 1==auth, 2==auth-int, 4==auth-conf
        byte 1-3: the max length for any buffer sent back and forth on
            this connection. (big endian)
        the rest of the buffer: the authorization user name in UTF-8 -
            not null terminated.

        So, we write the max length and authorization user name first, then
        overwrite the first byte of the buffer with the qop.  This is ok since
        the max length is writen out in big endian.
        """
        i = len(self.user)
        fmt = '!I' + str(i) + 's'
        outdata = create_string_buffer(4 + i)
        struct.pack_into(fmt, outdata, 0, self.max_buffer, self.user)

        qop = 1
        if self.qop == 'auth-int':
            qop = 2
        elif self.qop == 'auth-conf':
            qop = 4
        struct.pack_into('!B', outdata, 0, qop)

        encodeddata = base64.b64encode(outdata)

        kerberos.authGSSClientWrap(self.context, encodeddata)
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
                raise StandardError("Error: confidentiality requested, but not honored by the server.")
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
