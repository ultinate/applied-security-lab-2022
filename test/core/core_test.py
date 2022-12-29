import os
import unittest
import tempfile

os.environ["UNITTEST"] = "UNITTEST"
from source.core.app.api import Stats, parse_index_file


class CoreTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp_index = tempfile.NamedTemporaryFile()
        with open(self.tmp_index.name, mode='w') as f:
            f.write("\n".join([
                'R	231021083846Z	221021084932Z	1000	unknown	/C=CH/ST=Zurich/O=iMovies, Inc./CN=nate@imovies.ch',
                'V	231021084950Z		1001	unknown	/C=CH/ST=Zurich/O=iMovies, Inc./CN=nate22@imovies.ch',
            ]))

    def test_current_serial(self):
        test_stats = Stats()
        tmp = tempfile.NamedTemporaryFile()
        with open(tmp.name, mode='w') as f:
            f.write('02\n')
        result = test_stats.read_current_serial(tmp.name)
        self.assertEqual('02', result)

    def test_parse_index_file(self):
        result = parse_index_file(self.tmp_index.name)
        expected_result = [
            {'id': '1000', 'name': 'nate@imovies.ch', 'status': 'revoked'},
            {'id': '1001', 'name': 'nate22@imovies.ch', 'status': 'valid'}
        ]
        self.assertEqual(expected_result, result)


if __name__ == '__main__':
    unittest.main()
