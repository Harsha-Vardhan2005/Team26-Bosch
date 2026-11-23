"""Allow running the Guardian as ``python -m guardian``."""

import sys

from guardian.cli import main

sys.exit(main())

