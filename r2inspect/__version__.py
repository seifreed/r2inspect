"""Version information for r2inspect."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("r2inspect")
except PackageNotFoundError:
    __version__ = "0+unknown"

__author__ = "Marc Rivero"
__author_email__ = "mriverolopez@gmail.com"
__license__ = "GPL-3.0"
__url__ = "https://github.com/seifreed/r2inspect"
