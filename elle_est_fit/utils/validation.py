"""
Validation utilities for the Elle-Est-Fit framework.
"""

import re
from urllib.parse import urlparse

from ..exceptions import ValidationError


def validate_url(url: str) -> None:
    if not url:
        raise ValidationError("URL cannot be empty")
    
    if '{}' not in url:
        raise ValidationError("URL must contain a '{}' placeholder for the LFI parameter")
    
    parsed = urlparse(url)
    
    # Check if scheme and netloc are present
    if not parsed.scheme or not parsed.netloc:
        raise ValidationError("URL must include protocol and domain (e.g., http://example.com)")
    
    if parsed.scheme not in ['http', 'https']:
        raise ValidationError(f"Unsupported URL scheme: {parsed.scheme}")