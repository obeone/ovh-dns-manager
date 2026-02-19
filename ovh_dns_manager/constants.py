"""
Constants used throughout the OVH DNS Manager package.

This module centralizes all constant values including supported DNS record
types, validation regexes, and filesystem paths for credential storage.

Copyright (c) 2026 Snapp'
Author: Yannis Duvignau (yduvignau@snapp.fr)
"""

import os
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

# Credentials file path: ~/.config/ovh-dns-manager/credentials.env
# Respects XDG_CONFIG_HOME if set, otherwise defaults to ~/.config
_CONFIG_DIR = Path(
    os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
) / "ovh-dns-manager"
ENV_FILE = _CONFIG_DIR / "credentials.env"
