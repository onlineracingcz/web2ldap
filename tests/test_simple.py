# from Python's standard lib
import unittest

import web2ldap

class TestFunctions(unittest.TestCase):

    def test_cmp(self):
        """
        test function web2ldap.cmp()
        """
        self.assertEqual(web2ldap.cmp(1, 2), -1)
        self.assertEqual(web2ldap.cmp('a', 'b'), -1)
        self.assertEqual(web2ldap.cmp(0, 0), 0)
        self.assertEqual(web2ldap.cmp('a', 'a'), 0)
        self.assertEqual(web2ldap.cmp('b', 'a'), 1)


if __name__ == '__main__':
    unittest.main()
