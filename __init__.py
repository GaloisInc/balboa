from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent
"""A `Path` object corresponding to the root of the rocky repository."""

IS_IN_CI = os.environ.get("ROCKY_IS_IN_CI") == "1"
"""A boolean which is true if this command is being run on CI."""
