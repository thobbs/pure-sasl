import base64
import hashlib
import hmac
import random
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


## functions used in DigestMD5 which were originally defined in the now-removed util module

def bytes(text):
    """
    Convert Unicode text to UTF-8 encoded bytes.

    Since Python 2.6+ and Python 3+ have similar but incompatible
    signatures, this function unifies the two to keep code sane.

    :param text: Unicode text to convert to bytes
    :rtype: bytes (Python3), str (Python2.6+)
    """
    if sys.version_info < (3, 0):
        import __builtin__
        return __builtin__.bytes(text)
    else:
        import builtins
        if isinstance(text, builtins.bytes):
            # We already have bytes, so do nothing
            return text
        if isinstance(text, list):
            # Convert a list of integers to bytes
            return builtins.bytes(text)
        else:
            # Convert UTF-8 text to bytes
            return builtins.bytes(text, encoding='utf-8')


def quote(text):
    """
    Enclose in quotes and escape internal slashes and double quotes.

    :param text: A Unicode or byte string.
    """
    text = bytes(text)
    return b'"' + text.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'


def num_to_bytes(num):
    """
    Convert an integer into a four byte sequence.

    :param integer num: An integer to convert to its byte representation.
    """
    bval = b''
    bval += bytes(chr(0xFF & (num >> 24)))
    bval += bytes(chr(0xFF & (num >> 16)))
    bval += bytes(chr(0xFF & (num >> 8)))
    bval += bytes(chr(0xFF & (num >> 0)))
    return bval


def bytes_to_num(bval):
    """
    Convert a four byte sequence to an integer.

    :param bytes bval: A four byte sequence to turn into an integer.
    """
    num = 0
    num += ord(bval[0] << 24)
    num += ord(bval[1] << 16)
    num += ord(bval[2] << 8)
    num += ord(bval[3])
    return num

# TODO: incomplete, not tested
class DigestMD5Mechanism(Mechanism):

    name = "DIGEST-MD5"
    score = 30

    allows_anonymous = False
    uses_plaintext = False

    enc_magic = 'Digest session key to client-to-server signing key magic'
    dec_magic = 'Digest session key to server-to-client signing key magic'

    def __init__(self, sasl, username=None, password=None, **props):
        Mechanism.__init__(self, sasl)
        self.username = username
        self.password = password

        self.qops = self.sasl.qops
        self.qop = b'auth'
        self.max_buffer = self.sasl.max_buffer

        self._rspauth_okay = False
        self._digest_uri = None
        self._a1 = None
        self._enc_buf = b''
        self._enc_key = None
        self._enc_seq = 0
        self._dec_buf = b''
        self._dec_key = None
        self._dec_seq = 0

    def dispose(self):
        self._rspauth_okay = None
        self._digest_uri = None
        self._a1 = None
        self._enc_buf = b''
        self._enc_key = None
        self._enc_seq = 0
        self._dec_buf = b''
        self._dec_key = None
        self._dec_seq = 0

        self.password = None
        self.key_hash = None
        self.realm = None
        self.nonce = None
        self.cnonce = None
        self.nc = 0

    def _MAC(self, seq, msg, key):
        mac = hmac.HMAC(key=key, digestmod=hashlib.md5)
        seqnum = num_to_bytes(seq)
        mac.update(seqnum)
        mac.update(msg)
        return mac.digest()[:10] + b'\x00\x01' + seqnum

    def wrap(self, outgoing):
        if self.qop == 'auth-int':
            result = b''
            # Leave buffer space for the MAC
            mbuf = self.max_buffer - 10 - 2 - 4

            while outgoing:
                msg = outgoing[:mbuf]
                mac = self._MAC(self._enc_seq, msg, self._enc_key)
                self._enc_seq += 1
                msg += mac
                result += num_to_bytes(len(msg)) + msg
                outgoing = outgoing[mbuf:]

            return result
        elif self.qop == 'auth-conf':
            raise NotImplementedError('auth-conf QoP not yet implemented for DIGEST-MD5')
        else:
            return outgoing

    def unwrap(self, incoming):
        if self.qop == 'auth-int':
            incoming = b'' + incoming
            result = b''

            while len(incoming) > 4:
                num = bytes_to_num(incoming)
                if len(incoming) < (num + 4):
                    return result

                mac = incoming[4:4 + num]
                incoming[4 + num:]
                msg = mac[:-16]

                mac_conf = self._MAC(self._dec_seq, msg, self._dec_key)
                if mac[-16:] != mac_conf:
                    self._dec_seq = None
                    return result

                self._dec_seq += 1
                result += msg

            return result
        elif self.qop == 'auth-conf':
            raise NotImplementedError('auth-conf QoP not yet implemented for DIGEST-MD5')
        else:
            return incoming

    def response(self):
        required_props = ['username']
        if not getattr(self, 'key_hash', None):
            required_props.append('password')
        self._fetch_properties(*required_props)

        resp = {}
        resp['qop'] = self.qop

        if getattr(self, 'realm', None) is not None:
            resp['realm'] = quote(self.realm)

        resp['username'] = quote(bytes(self.username))
        resp['nonce'] = quote(self.nonce)
        if self.nc == 0:
            self.cnonce = bytes('%s' % random.random())[2:]
        resp['cnonce'] = quote(self.cnonce)
        self.nc += 1
        resp['nc'] = bytes('%08x' % self.nc)

        self._digest_uri = bytes(self.sasl.service) + b'/' + \
                                                        bytes(self.sasl.host)
        resp['digest-uri'] = quote(self._digest_uri)

        a2 = b'AUTHENTICATE:' + self._digest_uri
        if self.qop != b'auth':
            a2 += b':00000000000000000000000000000000'
            resp['maxbuf'] = b'16777215'  # 2**24-1
        resp['response'] = self.gen_hash(a2)
        return b','.join([bytes(k) + b'=' + bytes(v) for k, v in resp.items()])

    def parse_challenge(self, challenge):
        ret = {}
        var = b''
        val = b''
        in_var = True
        in_quotes = False
        new = False
        escaped = False
        for c in challenge:
            if sys.version_info >= (3, 0):
                c = bytes([c])
            if in_var:
                if c.isspace():
                    continue
                if c == b'=':
                    in_var = False
                    new = True
                else:
                    var += c
            else:
                if new:
                    if c == b'"':
                        in_quotes = True
                    else:
                        val += c
                    new = False
                elif in_quotes:
                    if escaped:
                        escaped = False
                        val += c
                    else:
                        if c == b'\\':
                            escaped = True
                        elif c == b'"':
                            in_quotes = False
                        else:
                            val += c
                else:
                    if c == b',':
                        if var:
                            ret[var] = val
                        var = b''
                        val = b''
                        in_var = True
                    else:
                        val += c
        if var:
            ret[var] = val
        return ret

    def gen_hash(self, a2):
        if not getattr(self, 'key_hash', None):
            key_hash = hashlib.md5()
            user = bytes(self.username)
            password = bytes(self.password)
            realm = bytes(self.realm)
            kh = user + b':' + realm + b':' + password
            key_hash.update(kh)
            self.key_hash = key_hash.digest()

        a1 = hashlib.md5(self.key_hash)
        a1h = b':' + self.nonce + b':' + self.cnonce
        a1.update(a1h)
        response = hashlib.md5()
        self._a1 = a1.digest()
        self._enc_key = hashlib.md5(self._a1 + self.enc_magic).digest()
        self._dec_key = hashlib.md5(self._a1 + self.dec_magic).digest()
        rv = bytes(a1.hexdigest().lower())
        rv += b':' + self.nonce
        rv += b':' + bytes('%08x' % self.nc)
        rv += b':' + self.cnonce
        rv += b':' + self.qop
        rv += b':' + bytes(hashlib.md5(a2).hexdigest().lower())
        response.update(rv)
        return bytes(response.hexdigest().lower())

    def authenticate_server(self, cmp_hash):
        a2 = b':' + self._digest_uri
        if self.qop != b'auth':
            a2 += b':00000000000000000000000000000000'
        if self.gen_hash(a2) == cmp_hash:
            self._rspauth_okay = True

    def process(self, challenge=None):
        if challenge is None:
            needed = ['username', 'realm', 'nonce', 'key_hash',
                      'nc', 'cnonce', 'qops']
            if all(getattr(self, p, None) is not None for p in needed):
                return self.response()
            else:
                return None

        challenge_dict = self.parse_challenge(challenge)
        if self.sasl.mutual_auth and b'rspauth' in challenge_dict:
            self.authenticate_server(challenge_dict[b'rspauth'])
        else:
            if b'realm' not in challenge_dict:
                self._fetch_properties('realm')
                challenge_dict[b'realm'] = self.realm

            for key in (b'nonce', b'realm'):
                if key in challenge_dict:
                    setattr(self, key, challenge_dict[key])

            self.nc = 0
            if b'qop' in challenge_dict:
                server_offered_qops = [x.strip() for x in challenge_dict[b'qop'].split(b',')]
            else:
                server_offered_qops = [b'auth']
            self._pick_qop(set(server_offered_qops))

            if b'maxbuf' in challenge_dict:
                self.max_buffer = min(
                        self.sasl.max_buffer, int(challenge_dict[b'maxbuf']))

            return self.response()

    @property
    def complete(self):
        """
        """
        if not self.sasl.mutual_auth:
            return True

        if self._rspauth_okay and self.qop == b'auth-int':
            self._enc_key = hashlib.md5(self._a1 + self.enc_magic).digest()
            self._dec_key = hashlib.md5(self._a1 + self.dec_magic).digest()
            self.encoding = True
        return self._rspauth_okay


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
