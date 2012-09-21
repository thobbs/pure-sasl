import puresasl.mechanism as mech_mod
from puresasl import SASLError


def _require_mech(f):
    def wrapped_f(self, *args, **kwargs):
        if not self._chosen_mech:
            raise SASLError("A mechanism has not been chosen yet")
        return f(self, *args, **kwargs)

    wrapped_f.__name__ = f.__name__
    return wrapped_f


class SASLClient(object):

    def __init__(self, host, service, mechanism=None, authorization_id=None,
            callback=None, qops=(b'auth',), mutual_auth=False, max_buffer=65536,
            **mechanism_props):
        self.host = host
        self.service = service
        self.authorization_id = authorization_id
        self.mechanism = mechanism
        self.callback = callback
        self.qops = qops
        self.mutual_auth = mutual_auth
        self.max_buffer = max_buffer

        self._mech_props = mechanism_props
        if self.mechanism is not None:
            mech_class = mech_mod.mechanisms[mechanism]
            self._chosen_mech = mech_class(self, **self._mech_props)
        else:
            self._chosen_mech = None

    @_require_mech
    def process(self, challenge=None):
        return self._chosen_mech.process(challenge)

    @_require_mech
    def wrap(self, outgoing):
        return self._chosen_mech.wrap(outgoing)

    @_require_mech
    def unwrap(self, incoming):
        return self._chosen_mech.unwrap(incoming)

    @property
    def complete(self):
        """ Has negotiation completed successfully? """
        if not self._chosen_mech:
            raise SASLError("A mechanism has not been chosen yet")
        return self._chosen_mech.complete

    @_require_mech
    def dispose(self):
        """ Clear all sensitive data """
        self._chosen_mech.dispose()

    def choose_mechanism(self, mechanism_choices, allow_anonymous=True,
            allow_plaintext=True, allow_active=True, allow_dictionary=True):
        """
        Choose the most secure mechanism from a list of mechanisms.
        """
        candidates = [mech_mod.mechanisms[choice]
                for choice in mechanism_choices
                if choice in mech_mod.mechanisms]

        if not allow_anonymous:
            candidates = [m for m in candidates if not m.allows_anonymous]
        if not allow_plaintext:
            candidates = [m for m in candidates if not m.uses_plaintext]
        if not allow_active:
            candidates = [m for m in candidates if m.active_safe]
        if not allow_dictionary:
            candidates = [m for m in candidates if m.allow_dictionary]

        if not candidates:
            raise SASLError("None of the mechanisms listed meet all "
                    "required properties")

        # Pick the best mechanism based on its security score
        mech_class = max(candidates, key=lambda mech: mech.score)
        self.mechanism = mech_class.name
        self._chosen_mech = mech_class(self, **self._mech_props)
