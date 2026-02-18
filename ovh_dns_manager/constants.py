"""
Constants used throughout the OVH DNS Manager package.

This module centralizes all constant values including supported DNS record
types, validation regexes, and filesystem paths for credential storage.
"""

import re
import sys
from pathlib import Path

# Supported DNS record types for create/list/delete operations
SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV"]

# Regex for validating domain names (RFC 1123 compliant)
DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# Regex for validating subdomain labels
SUBDOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
)

# Application path: use the directory containing the .exe for frozen builds,
# otherwise the package directory
if getattr(sys, 'frozen', False):
    APPLICATION_PATH = Path(sys.executable).parent
else:
    APPLICATION_PATH = Path(__file__).parent.parent

# Path to the .env credentials file
ENV_FILE = APPLICATION_PATH / ".env"
