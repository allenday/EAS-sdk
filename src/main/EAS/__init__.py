# Import the main EAS class
from .core import EAS

# Import configuration helpers
from . import config

# Make EAS available at package level
__all__ = ['EAS', 'config']

