"""PhishScope — offline, explainable phishing-URL risk scoring in pure Python."""

from .analyzer import Flag, Report, analyze

__version__ = "1.0.1"

__all__ = ["Flag", "Report", "analyze", "__version__"]
