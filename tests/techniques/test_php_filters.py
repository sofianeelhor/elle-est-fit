"""
Tests for the PHP Filter technique.
"""
import unittest
from unittest import mock

from elle_est_fit.techniques.php_filters import PHPFilterTechnique
from elle_est_fit.exceptions import ExecutionError


class TestPHPFilterTechnique(unittest.TestCase):
    """Tests for the PHP Filter technique."""
    
    def test_initialization(self):
        """Test initialization of the technique."""
        technique = PHPFilterTechnique(
            target="http://example.com/?page={}"
        )
        self.assertEqual(technique.name, "php_filters")
        self.assertEqual(technique.description, "LFI to RCE via PHP filter chain")
        self.assertEqual(technique.wrapper_path, "php://temp")
    
    @mock.patch.object(PHPFilterTechnique, 'leak_function')
    def test_check_vulnerable(self, mock_leak):
        """Test check method when target is vulnerable."""
        # Set up the mock to return a response containing the detection string
        mock_leak.return_value = "Some content ELLEESTFIT_abcdefgh more content"
        
        technique = PHPFilterTechnique(
            target="http://example.com/?page={}"
        )
        technique.shell_token = "abcdefgh"  # Set the token to match the mock
        
        result = technique.check()
        self.assertTrue(result)
        mock_leak.assert_called_once()
