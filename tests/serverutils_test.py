import unittest

from src import Status


class ServerUtilsTestCase(unittest.TestCase):

    def test_HTTP_STATUS_tuples(self):
        for s in Status:
            self.assertIsInstance(s, int)
            self.assertIsInstance(s.code, int)
            self.assertEqual(s, s.code)

            self.assertIsInstance(s.header, str)
            self.assertIsInstance(s.descriptor, str)


if __name__ == '__main__':
    unittest.main()
