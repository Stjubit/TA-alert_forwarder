
import os
import sys
import re
from os.path import dirname

ADDON_NAME = 'TA-alert_forwarder'
pattern = re.compile(r'[\\/]etc[\\/]apps[\\/][^\\/]+[\\/]bin[\\/]?$')
new_paths = [path for path in sys.path if not pattern.search(path) or ADDON_NAME in path]
new_paths.insert(0, os.path.join(dirname(dirname(__file__)), "lib"))
new_paths.insert(0, os.path.sep.join([os.path.dirname(__file__), ADDON_NAME]))
sys.path = new_paths
