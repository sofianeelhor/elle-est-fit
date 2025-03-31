"""
Tests for the core functionality of Elle-Est-Fit.
"""
import unittest
from unittest import mock

from elle_est_fit.core import LFI
from elle_est_fit.exceptions import ValidationError


class TestLFI(unittest.TestCase):
    """Tests for the LFI class."""
    
    def test_initialization_with_target(self):
        """Test initialization with a target URL."""
        lfi = LFI(target="http://example.com/?page={}")
        self.assertEqual(lfi.target, "http://example.com/?page={}")
        self.assertIsNone(lfi.technique_name)
        self.assertFalse(lfi.double_url_encode)
        self.assertIsNone(lfi.tamper)
