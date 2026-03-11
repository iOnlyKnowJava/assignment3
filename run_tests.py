import unittest
import sys

from gradescope_utils.autograder_utils.json_test_runner import JSONTestRunner
from pathlib import Path

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover('tests')
    stream = open('results.json', 'w')
    JSONTestRunner(visibility='visible', stream=stream).run(suite)
