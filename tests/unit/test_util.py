try:
    import unittest2 as unittest
except ImportError:
    import unittest  # noqa

import six

from puresasl.util import bytes


class UtilTest(unittest.TestCase):

    def test_bytes(self):
        self.assertEqual(bytes(b'string'), six.b('string'))
        self.assertEqual(bytes('string'), six.b('string'))
        self.assertEqual(bytes(u'string'), six.b('string'))
        self.assertEqual(bytes([1, 2, 3]), six.b(str([1, 2, 3])))  # py2 -- probably not intended for py3

        self.assertRaises(UnicodeEncodeError, bytes, u"\U0001F44D")
