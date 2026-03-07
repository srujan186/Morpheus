# conftest.py — adds sandbox/ and validators/ to sys.path for pytest
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))