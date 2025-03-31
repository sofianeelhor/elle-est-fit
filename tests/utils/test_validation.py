"""
Tests for the validation utilities.
"""
import unittest

from elle_est_fit.utils.validation import validate_url
from elle_est_fit.exceptions import ValidationError


class TestValidation(unittest.TestCase):
    """Tests for the validation utilities."""

    def test_validate_url_valid(self):
        """Test validation of a valid URL."""
        # Should not raise an exception
        validate_url("http://example.com/?page={}")

    def test_validate_url_invalid_empty(self):
        """Test validation of an empty URL."""
        with self.assertRaises(ValidationError):
            validate_url("")

    def test_validate_url_invalid_no_placeholder(self):
        """Test validation of a URL without placeholder."""
        with self.assertRaises(ValidationError):
            validate_url("http://example.com/?page=test")

    def test_validate_url_invalid_no_scheme(self):
        """Test validation of a URL without scheme."""
        with self.assertRaises(ValidationError):
            validate_url("example.com/?page={}")
