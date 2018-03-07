try:
    import unittest2 as unittest
except ImportError:
    import unittest  # noqa

from puresasl import SASLError
from puresasl.client import SASLClient
from puresasl.mechanisms import AnonymousMechanism, PlainMechanism, mechanisms, DigestMD5Mechanism


class SASLClientTest(unittest.TestCase):

    def test_init(self):
        # defaults
        SASLClient('localhost')

        # with mechanism
        sasl_client = SASLClient('localhost', mechanism=AnonymousMechanism.name)
        self.assertIsInstance(sasl_client._chosen_mech, AnonymousMechanism)
        self.assertIs(sasl_client._chosen_mech.sasl, sasl_client)

        # invalid mech
        self.assertRaises(SASLError, SASLClient, 'localhost', mechanism='WRONG')

    def test_chosen_mechanism(self):
        client = SASLClient('localhost', mechanism=PlainMechanism.name, username='user', password='pass')
        self.assertTrue(client.process())
        self.assertTrue(client.complete)
        msg = 'msg'
        self.assertEqual(client.wrap(msg), msg)
        self.assertEqual(client.unwrap(msg), msg)
        client.dispose()

    def test_unchosen_mechanism(self):
        client = SASLClient('localhost')
        self.assertRaises(SASLError, client.process)
        self.assertRaises(SASLError, client.wrap, 'msg')
        self.assertRaises(SASLError, client.unwrap, 'msg')
        with self.assertRaises(SASLError):
            client.complete
        self.assertRaises(SASLError, client.dispose)

    def test_choose_mechanism(self):
        client = SASLClient('localhost', service='something')
        choices = ['invalid']
        self.assertRaises(SASLError, client.choose_mechanism, choices)

        choices = [m for m in mechanisms.values() if m is not DigestMD5Mechanism]
        mech_names = set(m.name for m in choices)
        client.choose_mechanism(mech_names)
        self.assertIsInstance(client._chosen_mech, max(choices, key=lambda m: m.score))

        anon_names = set(m.name for m in choices if m.allows_anonymous)
        client.choose_mechanism(anon_names)
        self.assertIn(client.mechanism, anon_names)
        self.assertRaises(SASLError, client.choose_mechanism, anon_names, allow_anonymous=False)

        plain_names = set(m.name for m in choices if m.uses_plaintext)
        client.choose_mechanism(plain_names)
        self.assertIn(client.mechanism, plain_names)
        self.assertRaises(SASLError, client.choose_mechanism, plain_names, allow_plaintext=False)

        not_active_names = set(m.name for m in choices if not m.active_safe)
        client.choose_mechanism(not_active_names)
        self.assertIn(client.mechanism, not_active_names)
        self.assertRaises(SASLError, client.choose_mechanism, not_active_names, allow_active=False)

        not_dict_names = set(m.name for m in choices if not m.dictionary_safe)
        client.choose_mechanism(not_dict_names)
        self.assertIn(client.mechanism, not_dict_names)
        self.assertRaises(SASLError, client.choose_mechanism, not_dict_names, allow_dictionary=False)
