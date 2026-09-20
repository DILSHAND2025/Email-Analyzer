"""Root configuration for pytest and test runners."""

import os
import sys
from pathlib import Path

# Ensure workspace root is always at the beginning of sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
