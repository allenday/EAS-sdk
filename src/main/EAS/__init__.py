# Import the main EAS class
# Import configuration helpers
from . import config
from .core import EAS

# Make EAS available at package level
__all__ = ["EAS", "config"]
